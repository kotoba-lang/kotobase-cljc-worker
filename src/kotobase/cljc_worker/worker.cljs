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
            [kotobase.ipns :as ipns]
            ["@ipld/dag-cbor" :as dag-cbor]
            ["@noble/curves/ed25519.js" :refer [ed25519]]))

;; ── CACAO verify (byte-exact port of aozora.pds.auth/verify-cacao) ──────────

(defn- expired?
  "true iff `exp` (an ISO date string, or nil/absent -- no expiry check in
  that case, per this fn's own existing 'expiry-if-present' scope) denotes
  a time at or before now. `js/Date.parse` returns NaN (not nil, not a
  throw) on an unparseable string, and NaN < anything is FALSE in JS -- so
  a naive `(< (js/Date.parse exp) now)` treats a malformed :exp as
  'never expired', permanently valid. A malformed-but-present :exp is
  therefore treated as expired here (fail closed), matching the already-
  fixed sibling implementations (net-kotobase's kotobase-cf-wasm.auth/
  parse-epoch-sec and clj-edge's kotobase.edge-cacao/parse-utc-seconds,
  both js/Number.isFinite-gated for the same reason)."
  [exp]
  (and exp
       (let [parsed (js/Date.parse exp)]
         (or (not (js/Number.isFinite parsed))
             (< parsed (.getTime (js/Date.)))))))

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
          expired? (expired? exp)
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
       ;; gobj/get, NOT (.-KOTOBASE_OPERATOR_DIDS env): the direct property access
       ;; is renamed under :advanced and reads undefined (the same Closure-rename
       ;; that collapsed the block prefix). That is invisible while the allowlist
       ;; is empty ("any valid issuer"), but would SILENTLY IGNORE a configured
       ;; production allowlist — i.e. accept any signer — so it must be extern-safe.
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
  `(.-KOTOBASE_B2_PREFIX env)`: under :advanced the direct property access is
  renamed and silently reads undefined (same Closure-rename class as the PRF
  extension bug), which collapsed the prefix to \"\" and scattered blocks at the
  bucket root regardless of the configured var."
  [env]
  (let [v (gobj/get env "KOTOBASE_B2_PREFIX")]
    (if (seq v) (str v "/") "")))

;; ── read / write orchestration over R2 ───────────────────────────────────────

(defn- run-read
  "Reads (datoms/q/pull/diagHydrateCost): trampoline the sync handler through
  R2 blocks. The graph head is read up front (one R2 text get) and injected
  as a constant. `:async-get-fn` is a DIRECT R2 byte fetch (bypassing
  with-blocks entirely) -- only diagHydrateCost reads it (ADR-2607120730
  follow-up); every other method ignores it."
  [^js bucket pfx method body]
  (-> (r2/r2-get-text bucket (r2/head-key pfx (:graph body)))
      (.then (fn [head-chain]
               (r2/with-blocks
                 (fn [cid] (r2/r2-get-bytes bucket (r2/block-key pfx cid)))
                 (fn [sync-get]
                   (h/handle {:get-fn sync-get :head-get (constantly head-chain)
                              :async-get-fn (fn [cid] (r2/r2-get-bytes bucket (r2/block-key pfx cid)))}
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
  "After a successful pure write (transact OR fold): flush the buffered
  blocks (always safe to write even on an eventual CAS loss — content-
  addressed, so a retry's blocks are either identical or simply orphaned,
  never corrupting), then attempt the conditional head write. A response
  with no `:commit` (a real error, or a fold that found nothing to fold)
  skips the CAS entirely — nothing to write, nothing to retry.
  → Promise<{:resp map :cas-ok? bool}>."
  [^js bucket pfx graph etag resp buffer]
  (if (nil? (:commit resp))
    (js/Promise.resolve {:resp resp :cas-ok? true})
    (-> (js/Promise.all
         (clj->js (map (fn [[cid bytes]] (r2/r2-put-bytes bucket (r2/block-key pfx cid) bytes))
                       @buffer)))
        (.then (fn [_] (r2/r2-put-head-if-match bucket (r2/head-key pfx graph) (:commit resp) etag)))
        (.then (fn [cas-ok?] {:resp resp :cas-ok? cas-ok?})))))

(defn run-write-attempt
  "One CAS round for a head-mutating method (transact or fold): read the
  head + its etag, run the pure handler against that snapshot, then
  flush-blocks-and-cas-head!. → Promise<{:resp map :cas-ok? bool}>;
  :cas-ok? false means another writer's head update landed first — the
  caller retries from a fresh head read.

  :get-fn is a read-your-own-writes merge of `buffer` (this call's own
  not-yet-flushed :put!s) over the with-blocks trampoline, NOT the
  trampoline alone (INCIDENT 2607032800, \"worker commit! null.length\"):
  do-transact's own novelty_size re-reads the chain-cid it JUST committed
  before this fn ever flushes it to R2. Without the merge, with-blocks'
  sync-get throws missing-block (nothing cached yet) on that cid, the
  trampoline fetches it from R2 — a genuine miss, the block only exists in
  `buffer` — caches the miss AS nil, and retries; the retry's sync-get
  then returns nil WITHOUT throwing (nil is a cached hit), and
  ipld/decode nil crashes with `Cannot read properties of null (reading
  'length')`. handler.cljc's try/catch has no :block-miss on THAT
  exception (a plain TypeError, not a missing-block ex-info), so it's
  swallowed into a normal-looking `{:ok false :error \"InternalError\"
  ...}` response instead of a promise rejection — do-transact silently
  fails this way on every call, and do-fold hits the identical pattern
  reading back its own fold!-written blocks (the reason
  FOLD_CRON_ENABLED was left at 0 downstream in app-aozora).
  Reproduced independent of R2 (a pure-Node repro against ANY genuinely
  async store hits the same crash) and fixed the same way in this repo's
  sibling browser shell, kotoba-lang/kotobase-browser-worker."
  [^js bucket pfx method body auth-did]
  (let [buffer (atom {})
        graph  (:graph body)]
    (-> (r2/r2-get-head bucket (r2/head-key pfx graph))
        (.then (fn [{:keys [chain etag]}]
                 (-> (r2/with-blocks
                      (fn [cid] (r2/r2-get-bytes bucket (r2/block-key pfx cid)))
                      (fn [sync-get]
                        (h/handle {:get-fn (fn [cid] (if (contains? @buffer cid)
                                                        (get @buffer cid)
                                                        (sync-get cid)))
                                   :put! (fn [cid bytes] (swap! buffer assoc cid bytes))
                                   :head-get (constantly chain)
                                   :head-put! (fn [_ _] nil)   ; head CAS'd below
                                   ;; ADR-2607120730 Part 1: DIRECT (unbuffered)
                                   ;; R2 read/write, NOT threaded through
                                   ;; `buffer` -- do-fold's cache-put! must
                                   ;; land immediately so an attempt that
                                   ;; hydrates OK but exceeds its CPU budget
                                   ;; later still leaves the cache populated
                                   ;; for the next retry (a write buffered
                                   ;; here would only flush AFTER the whole
                                   ;; response returns, i.e. never, on
                                   ;; exactly that failure). do-transact never
                                   ;; reads these keys, so providing them
                                   ;; unconditionally for every method is
                                   ;; harmless. Plain text put/get (R2
                                   ;; accepts a string body directly, same as
                                   ;; r2-put-head-if-match's head write) --
                                   ;; hydrate-db-cached's cache values are
                                   ;; already pr-str'd EDN strings, no byte
                                   ;; encoding needed.
                                   :cache-get (fn [k] (r2/r2-get-text bucket (str pfx k)))
                                   :cache-put! (fn [k v] (.put bucket (str pfx k) v))}
                                  method body auth-did)))
                     (.then (fn [resp] (flush-blocks-and-cas-head! bucket pfx graph etag resp buffer)))))))))

(defn run-write
  "transact/fold: CAS-guarded head advance (see run-write-attempt) with
  retry on lost races — never silently drops a commit whose blocks made it
  to R2; either the head lands or the caller gets ConcurrentWriteConflict
  after exhausting retries (loud failure beats silent data loss). Closes a
  real, confirmed-live race: every actor's createRecord lands on the SAME
  shared operator-identity graph, so overlapping writers (worker slowness
  widens the window; the PDS's own relay-ingest cron writes the same graph
  too) raced the OLD unconditional head .put — whichever landed last
  silently orphaned the other's commit (blocks stayed in R2, never
  corrupted, just unreachable from the head chain). See ADR-2607022330
  addendum 3."
  ([bucket pfx method body auth-did] (run-write bucket pfx method body auth-did 1))
  ([^js bucket pfx method body auth-did attempt]
   (-> (run-write-attempt bucket pfx method body auth-did)
       (.then (fn [{:keys [resp cas-ok?]}]
                (cond
                  cas-ok? resp
                  (>= attempt max-head-cas-attempts)
                  {:ok false :error "ConcurrentWriteConflict"
                   :message (str "head CAS lost the race " attempt " times")}
                  :else
                  (-> (delay-ms (min 800 (* 50 attempt)))
                      (.then (fn [_] (run-write bucket pfx method body auth-did (inc attempt)))))))))))

;; ── IPNS head / publish (com.etzhayyim.apps.kotoba.ipns.*, ADR-2607061800) ──
;;
;; UNAUTHENTICATED reads, signature-gated writes — a genuinely different trust
;; model from datomic.transact's CACAO+graph-derivation above, so it is its
;; own NSID family and its own key-value pair rather than another `case`
;; branch of `handle`. Reuses r2-get-head/r2-put-head-if-match's CAS pair
;; (built for the commit-chain string) by JSON-stringifying the whole signed
;; record as that "chain" string.
;;
;; KNOWN LEXICON/IMPLEMENTATION MISMATCH (owner-confirmed, not silently
;; papered over): ipns/head.json's query param is documented as `graph`
;; ("Graph CID ... IPNS name is derived from it"), but no graph-CID -> IPNS-
;; name derivation exists anywhere (`ipns.core/pubkey->name` derives a name
;; from an Ed25519 PUBKEY, not a graph CID). Storage below is keyed by the
;; signed record's own `:name` field instead, and the query/response param
;; actually read here is `name`, not `graph` -- fixing the lexicon itself is
;; a separate follow-up.

(defn- valid-sequence?
  "A `:sequence` value the rollback comparison below can safely `<=`.
  `(= x x)` is false for NaN (IEEE-754 self-inequality) -- needed because a
  non-numeric `:sequence` (e.g. a string) coerces to NaN under cljs's loose
  `<=`, and NaN compares false against everything, which would silently
  disable the rollback guard rather than rejecting the write."
  [x]
  (and (number? x) (= x x)))

(defn run-ipns-head [^js bucket pfx name]
  (if (str/blank? (or name ""))
    (js/Promise.resolve (json-response {:ok false :error "InvalidRequest" :message "missing name"} 400))
    (-> (r2/r2-get-text bucket (r2/ipns-key pfx name))
        (.then (fn [text]
                 (if (nil? text)
                   (json-response {:ok false :error "NotFound"} 404)
                   (json-response (js->clj (js/JSON.parse text) :keywordize-keys true) 200)))))))

(defn run-ipns-publish [^js bucket pfx body]
  (cond
    (not (:valid? (ipns/verify-head body)))
    (js/Promise.resolve (json-response {:ok false :error "InvalidSignature"} 401))

    (not (valid-sequence? (:sequence body)))
    (js/Promise.resolve (json-response {:ok false :error "InvalidSequence"} 400))

    :else
    (let [name (:name body)]
      (-> (r2/r2-get-head bucket (r2/ipns-key pfx name))
          (.then (fn [{:keys [chain etag]}]
                   (let [current (some-> chain js/JSON.parse (js->clj :keywordize-keys true))]
                     (cond
                       (and current (not (valid-sequence? (:sequence current))))
                       (json-response {:ok false :error "InvalidSequence"} 400)

                       (and current (<= (:sequence body) (:sequence current)))
                       (json-response {:ok false :error "SequenceRollback"} 409)

                       :else
                       (-> (r2/r2-put-head-if-match bucket (r2/ipns-key pfx name)
                                                    (js/JSON.stringify (clj->js body)) etag)
                           (.then (fn [ok?]
                                    (if ok?
                                      (json-response {:status "ok" :name name} 200)
                                      (json-response {:ok false :error "ConcurrentWriteConflict"} 409)))))))))))))

;; ── dispatch ─────────────────────────────────────────────────────────────────

(def ^:private ns-prefix (str "/xrpc/" h/datomic-ns "."))
(def ^:private ipns-ns-prefix "/xrpc/com.etzhayyim.apps.kotoba.ipns.")

(defn fetch-handler [^js req ^js env]
  (let [url (js/URL. (.-url req))
        path (.-pathname url)]
    (cond
      (= "OPTIONS" (.-method req)) (js/Promise.resolve (cors-preflight))

      (str/starts-with? path ipns-ns-prefix)
      (let [method (subs path (count ipns-ns-prefix))]
        (-> (case method
              "head" (run-ipns-head (.-BUCKET env) (prefix env) (.get (.-searchParams url) "name"))
              "publish"
              (-> (.json req)
                  (.catch (fn [_] #js {}))
                  (.then (fn [raw] (run-ipns-publish (.-BUCKET env) (prefix env)
                                                     (js->clj raw :keywordize-keys true)))))
              (js/Promise.resolve (json-response {:ok false :error "MethodNotImplemented" :method method} 404)))
            (.catch (fn [^js e]
                      (json-response {:ok false :error "InternalError" :message (.-message e)} 500)))))

      (not (str/starts-with? path ns-prefix))
      (js/Promise.resolve (json-response {:ok false :error "NotFound"} 404))
      :else
      (let [method (subs path (count ns-prefix))]
        (-> (.json req)
            (.catch (fn [_] #js {}))
            (.then (fn [raw]
                     (let [body (js->clj raw :keywordize-keys true)]
                       (case method
                         ("datoms" "q" "pull" "diagHydrateCost") (run-read (.-BUCKET env) (prefix env) method body)
                         "transact"
                         ;; kotobase transact sends :db_name (+ cacao), NOT :graph —
                         ;; the graph is DERIVED as canonical-graph(issuer, db_name)
                         ;; so a write always lands on the issuer's own graph.
                         (let [issuer (some-> (:cacao_b64 body) verify-cacao)]
                           (if-not (authorized? env issuer)
                             (js/Promise.resolve (json-response {:ok false :error "AuthRequired"} 403))
                             (let [graph (cid/canonical-graph issuer (:db_name body))]
                               (run-write (.-BUCKET env) (prefix env) "transact"
                                          (assoc body :graph graph) issuer))))
                         "fold"
                         ;; Maintenance op (ADR-2607032430 D1): an authorized caller
                         ;; (cron/ops, not necessarily the graph owner — one operator
                         ;; identity may fold many actors' graphs) names the :graph
                         ;; directly, unlike transact's derived graph.
                         (let [issuer (some-> (:cacao_b64 body) verify-cacao)]
                           (if-not (authorized? env issuer)
                             (js/Promise.resolve (json-response {:ok false :error "AuthRequired"} 403))
                             (run-write (.-BUCKET env) (prefix env) "fold" body issuer)))
                         (js/Promise.resolve {:ok false :error "MethodNotImplemented" :method method})))))
            (.then (fn [resp] (if (instance? js/Response resp) resp (json-response resp 200))))
            (.catch (fn [^js e]
                      (json-response {:ok false :error "InternalError" :message (.-message e)} 500))))))))

(def handler #js {:fetch fetch-handler})
