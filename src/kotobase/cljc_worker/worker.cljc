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

(defn- allowlisted? [^js env issuer graph]
  (let [csv (some-> (.-KOTOBASE_OPERATOR_DIDS env) str/trim)]
    (or (str/blank? (or csv ""))                      ; empty allowlist = accept any valid CACAO
        (and issuer (str/includes? (str "," csv ",") (str "," issuer ","))
             ;; issuer must own the graph it writes: kotobase/db/<did>/<db>
             (str/includes? (str graph) issuer)))))

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

(defn- prefix [env] (or (some-> (.-KOTOBASE_B2_PREFIX env) (str "/")) ""))

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

(defn- run-transact
  "transact: trampoline the hydrate READ, BUFFER all new blocks in memory, then
  flush the buffer to R2 and advance the graph head — R2 writes happen after the
  sync commit, never mid-walk."
  [^js bucket pfx body auth-did]
  (let [buffer (atom {})
        graph  (:graph body)]
    (-> (r2/r2-get-text bucket (r2/head-key pfx graph))
        (.then (fn [head-chain]
                 (r2/with-blocks
                   (fn [cid] (r2/r2-get-bytes bucket (r2/block-key pfx cid)))
                   (fn [sync-get]
                     (h/handle {:get-fn sync-get
                                :put! (fn [cid bytes] (swap! buffer assoc cid bytes))
                                :head-get (constantly head-chain)
                                :head-put! (fn [_ _] nil)}      ; head flushed below
                               "transact" body auth-did)))))
        (.then (fn [resp]
                 (if-not (:ok resp)
                   resp
                   ;; flush buffered blocks, then the new head, then reply
                   (-> (js/Promise.all
                        (clj->js (map (fn [[cid bytes]]
                                        (r2/r2-put-bytes bucket (r2/block-key pfx cid) bytes))
                                      @buffer)))
                       (.then (fn [_] (.put bucket (r2/head-key pfx graph) (:commit resp))))
                       (.then (fn [_] resp)))))))))

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
                         (let [issuer (some-> (:cacao_b64 body) verify-cacao)]
                           (if-not (allowlisted? env issuer (:graph body))
                             (js/Promise.resolve (json-response {:ok false :error "AuthRequired"} 403))
                             (run-transact (.-BUCKET env) (prefix env) body issuer)))
                         (js/Promise.resolve {:ok false :error "MethodNotImplemented" :method method})))))
            (.then (fn [resp] (if (instance? js/Response resp) resp (json-response resp 200))))
            (.catch (fn [^js e]
                      (json-response {:ok false :error "InternalError" :message (.-message e)} 500))))))))

(def handler #js {:fetch fetch-handler})
