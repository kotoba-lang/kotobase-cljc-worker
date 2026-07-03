(ns kotobase.cljc-worker.worker
  "workerd :esm entry — the filter-honoring CLJC replacement for the WASM
  kotobase datom worker (ADR-2607022330 addendum 2).

  Reads (datoms/q/pull) run the sync engine through the R2 block-miss trampoline;
  a write (transact) trampolines its hydrate read, buffers new blocks in memory,
  then flushes them to R2 and advances the graph head — so a read never
  rehydrates the whole graph and the ceiling-busting full-load is gone.

  Env bindings: BUCKET (R2), KOTOBASE_B2_PREFIX (var, block/head key prefix),
  KOTOBASE_OPERATOR_DIDS (var, optional CSV allowlist of transact issuers)."
  (:require [clojure.string :as str]
            [goog.object :as gobj]
            [kotobase.cljc-worker.handler :as h]
            [kotobase.cljc-worker.r2 :as r2]
            [kotobase.cacao :as cacao]
            [kotobase.cid :as cid]
            ["@ipld/dag-cbor" :as dag-cbor]
            ["@noble/curves/ed25519.js" :refer [ed25519]]))

;; ── CACAO verify (byte-exact port of aozora.pds.auth/verify-cacao) ──────────

(defn verify-cacao
  "→ issuer DID (string) | nil. Decodes the CACAO, recomputes its SIWE message,
  and Ed25519-verifies under the issuer's did:key. Same source the PDS mints/
  verifies with (kotobase.cacao), so client and worker can't drift."
  [cacao-b64]
  (try
    (let [^js env (.decode dag-cbor (cacao/base64->bytes cacao-b64))
          ^js p   (.-p env)
          iss (.-iss p)
          pub (cid/did-key->ed25519-pub iss)
          exp (.-exp p)
          expired? (and exp (< (js/Date.parse exp) (.getTime (js/Date.))))
          p-clj {:domain (.-domain p) :iss iss :aud (.-aud p) :version (.-version p)
                 :nonce (.-nonce p) :iat (.-iat p) :exp exp :statement (.-statement p)
                 :resources (vec (.-resources p))}
          msg (cacao/cacao-siwe-message p-clj)
          sig (cacao/base64url->bytes (.. env -s -s))]
      (when (and pub (not expired?) (.verify ed25519 sig (cid/text->bytes msg) pub))
        iss))
    (catch :default _ nil)))

(defn- authorized?
  "A transact is authorized iff a CACAO VERIFIED (issuer non-nil) and — when a
  non-empty operator allowlist is configured — the issuer is on it. An empty
  allowlist means 'any valid issuer', NOT 'no auth': a missing/invalid CACAO
  (issuer nil) is always rejected. GRAPH OWNERSHIP is structural, not checked
  here: the write graph is DERIVED as `canonical-graph(issuer, db_name)`, so an
  issuer can only ever write its own graph."
  [^js env issuer]
  (and issuer
       ;; gobj/get, NOT (.-KOTOBASE_OPERATOR_DIDS env): under :advanced release
       ;; the direct property access on an opaque runtime-provided `env` gets
       ;; Closure-renamed and silently reads undefined at the real Cloudflare
       ;; binding (confirmed empirically: KOTOBASE_B2_PREFIX vanished from the
       ;; compiled out/worker.js entirely — same class of bug, see `prefix`
       ;; below). Invisible while the allowlist is empty ("any valid issuer"),
       ;; but would SILENTLY IGNORE a configured production allowlist.
       (let [csv (some-> (gobj/get env "KOTOBASE_OPERATOR_DIDS") str/trim)]
         (or (str/blank? (or csv ""))
             (str/includes? (str "," csv ",") (str "," issuer ","))))))

;; ── HTTP ─────────────────────────────────────────────────────────────────────

(defn- json-response [body status]
  (js/Response. (js/JSON.stringify (clj->js body))
                #js {:status status
                     :headers #js {"content-type" "application/json"
                                   "access-control-allow-origin" "*"}}))

(defn- cors-preflight []
  (js/Response. nil #js {:status 204
                         :headers #js {"access-control-allow-origin" "*"
                                       "access-control-allow-methods" "GET, POST, OPTIONS"
                                       "access-control-allow-headers" "authorization, content-type"
                                       "access-control-max-age" "86400"}}))

(defn- prefix
  "Block/head key prefix from KOTOBASE_B2_PREFIX. Read via goog.object/get, NOT
  `(.-KOTOBASE_B2_PREFIX env)`: CONFIRMED empirically (grep the compiled
  out/worker.js — the literal name is entirely absent) that under :advanced
  release the direct property access on the runtime-opaque `env` gets
  Closure-renamed and silently reads undefined, collapsing the prefix to \"\"
  and scattering every block/head key at the bucket root regardless of the
  configured var — a distinct, additional way for writes/reads to land in
  the wrong keyspace, alongside the head-CAS race this same PR fixes."
  [^js env]
  (let [v (gobj/get env "KOTOBASE_B2_PREFIX")]
    (if (seq v) (str v "/") "")))

;; ── read / write orchestration over R2 ───────────────────────────────────────

(defn- run-read
  "Reads (datoms/q/pull): trampoline the sync handler through R2 blocks. The
  graph head is read up front (one R2 text get) and injected as a constant."
  [^js bucket pfx method body]
  (-> (r2/r2-get-text bucket (r2/head-key pfx (:graph body)))
      (.then (fn [head-chain]
               (r2/with-blocks
                 (fn [cid] (r2/r2-get-bytes bucket (r2/block-key pfx cid)))
                 (fn [sync-get]
                   (h/handle {:get-fn sync-get :head-get (constantly head-chain)}
                             method body nil)))))))

(defn- delay-ms [ms] (js/Promise. (fn [resolve _] (js/setTimeout resolve ms))))

(def ^:private max-head-cas-attempts
  "Every com.atproto.repo.createRecord across every actor lands on the SAME
  operator-identity yoro-social graph (ADR-2607022330 addendum 3), so
  contention is the common case under any real write volume, not a tail
  edge case — sized generously rather than tuned to a specific observed
  burst width."
  8)

(defn- flush-blocks-and-cas-head!
  "After a successful pure transact: flush the buffered blocks (always safe
  to write even on an eventual CAS loss — content-addressed, so a retry's
  blocks are either identical or simply orphaned, never corrupting), then
  attempt the conditional head write. → Promise<{:resp map :cas-ok? bool}>."
  [^js bucket pfx graph etag resp buffer]
  (if-not (:ok resp)
    (js/Promise.resolve {:resp resp :cas-ok? true})   ; real error, not a race — don't retry
    (-> (js/Promise.all
         (clj->js (map (fn [[cid bytes]] (r2/r2-put-bytes bucket (r2/block-key pfx cid) bytes))
                       @buffer)))
        (.then (fn [_] (r2/r2-put-head-if-match bucket (r2/head-key pfx graph) (:commit resp) etag)))
        (.then (fn [cas-ok?] {:resp resp :cas-ok? cas-ok?})))))

(defn- run-transact-attempt
  "One CAS round: read the head + its etag, run the pure handler against
  that snapshot, then flush-blocks-and-cas-head!. → Promise<{:resp map
  :cas-ok? bool}>; :cas-ok? false means another writer's head update landed
  first — the caller retries from a fresh head read."
  [^js bucket pfx body auth-did]
  (let [buffer (atom {})
        graph  (:graph body)]
    (-> (r2/r2-get-head bucket (r2/head-key pfx graph))
        (.then (fn [{:keys [chain etag]}]
                 (-> (r2/with-blocks
                      (fn [cid] (r2/r2-get-bytes bucket (r2/block-key pfx cid)))
                      (fn [sync-get]
                        (h/handle {:get-fn sync-get
                                   :put! (fn [cid bytes] (swap! buffer assoc cid bytes))
                                   :head-get (constantly chain)
                                   :head-put! (fn [_ _] nil)}   ; head CAS'd below
                                  "transact" body auth-did)))
                     (.then (fn [resp] (flush-blocks-and-cas-head! bucket pfx graph etag resp buffer)))))))))

(defn- run-transact
  "transact: CAS-guarded head advance (see run-transact-attempt) with retry
  on lost races — never silently drops a commit whose blocks made it to R2;
  either the head lands or the caller gets ConcurrentWriteConflict after
  exhausting retries (loud failure beats silent data loss)."
  ([bucket pfx body auth-did] (run-transact bucket pfx body auth-did 1))
  ([^js bucket pfx body auth-did attempt]
   (-> (run-transact-attempt bucket pfx body auth-did)
       (.then (fn [{:keys [resp cas-ok?]}]
                (cond
                  cas-ok? resp
                  (>= attempt max-head-cas-attempts)
                  {:ok false :error "ConcurrentWriteConflict"
                   :message (str "head CAS lost the race " attempt " times")}
                  :else
                  (-> (delay-ms (min 800 (* 50 attempt)))
                      (.then (fn [_] (run-transact bucket pfx body auth-did (inc attempt)))))))))))

;; ── dispatch ─────────────────────────────────────────────────────────────────

(def ^:private ns-prefix (str "/xrpc/" h/datomic-ns "."))

(defn fetch-handler [^js req ^js env]
  (let [url (js/URL. (.-url req))
        path (.-pathname url)]
    (cond
      (= "OPTIONS" (.-method req)) (js/Promise.resolve (cors-preflight))
      (not (str/starts-with? path ns-prefix))
      (js/Promise.resolve (json-response {:ok false :error "NotFound"} 404))
      :else
      (let [method (subs path (count ns-prefix))]
        (-> (.json req)
            (.catch (fn [_] #js {}))
            (.then (fn [raw]
                     (let [body (js->clj raw :keywordize-keys true)]
                       (case method
                         ("datoms" "q" "pull") (run-read (.-BUCKET env) (prefix env) method body)
                         "transact"
                         ;; kotobase transact sends :db_name (+ cacao), NOT :graph —
                         ;; the graph is DERIVED as canonical-graph(issuer, db_name)
                         ;; so a write always lands on the issuer's own graph.
                         (let [issuer (some-> (:cacao_b64 body) verify-cacao)]
                           (if-not (authorized? env issuer)
                             (js/Promise.resolve (json-response {:ok false :error "AuthRequired"} 403))
                             (let [graph (cid/canonical-graph issuer (:db_name body))]
                               (run-transact (.-BUCKET env) (prefix env)
                                             (assoc body :graph graph) issuer))))
                         (js/Promise.resolve {:ok false :error "MethodNotImplemented" :method method})))))
            (.then (fn [resp] (if (instance? js/Response resp) resp (json-response resp 200))))
            (.catch (fn [^js e]
                      (json-response {:ok false :error "InternalError" :message (.-message e)} 500))))))))

(def handler #js {:fetch fetch-handler})
