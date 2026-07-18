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
            [clojure.set :as set]
            [goog.object :as gobj]
            [ipld.core :as ipld]
            [kotobase.server.security.audit :as audit]
            [kotobase.server.security.authority :as authority]
            [kotobase.server.security.crypto :as crypto]
            [kotobase.server.security.keywrap :as keywrap]
            [kotobase.cljc-worker.handler :as h]
            [kotobase.cljc-worker.r2 :as r2]
            [kotobase.cacao :as cacao]
            [kotobase.cid :as cid]
            [kotobase.ipns :as ipns]
            [kotobase-peer.policy :as policy]
            ["@ipld/dag-cbor" :as dag-cbor]
            ["@noble/curves/ed25519.js" :refer [ed25519]]
            ["@noble/hashes/sha2.js" :refer [sha256]]))

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

(defn verify-cacao-full
  "→ {:did <issuer> :resources [<capability/graph strings>]} | nil. Same
  verification as verify-cacao, additionally surfacing the CACAO's
  resources so reads can apply capability-scoped visibility
  (ADR-2607174500 / ADR-2607050500 Phase 3)."
  [cacao-b64]
  (try
    (let [^js env (.decode dag-cbor (cacao/base64->bytes cacao-b64))
          ^js p   (.-p env)
          iss (.-iss p)
          pub (cid/did-key->ed25519-pub iss)
          exp (.-exp p)
          expired? (expired? exp)
          resources (vec (.-resources p))
          p-clj {:domain (.-domain p) :iss iss :aud (.-aud p) :version (.-version p)
                 :nonce (.-nonce p) :iat (.-iat p) :exp exp :statement (.-statement p)
                 :resources resources}
          msg (cacao/cacao-siwe-message p-clj)
          sig (cacao/base64url->bytes (.. env -s -s))]
      (when (and pub (not expired?) (.verify ed25519 sig (cid/text->bytes msg) pub))
        {:did iss :resources resources}))
    (catch :default _ nil)))

(def ^:private max-cacao-ttl-ms (* 10 60 1000))
(def ^:private max-clock-skew-ms (* 60 1000))

(defn- finite-time [s]
  (when (string? s)
    (let [n (js/Date.parse s)]
      (when (js/Number.isFinite n) n))))

(defn verify-cacao-context
  "Strict network-boundary CACAO verification. Unlike verify-cacao/full this
  validates the authority-relevant payload against server expectations and
  returns a normalized SecurityContext, never raw self-asserted authority.

  opts: :audience, :graph, :required-capabilities, :privileged-capabilities,
  :privileged-dids, :operation, :now-ms. Privileged capability strings are
  removed unless the issuer is locally trusted for them."
  [cacao-b64 {:keys [audience graph required-capabilities
                     privileged-capabilities privileged-dids allowed-capabilities
                     revoked-dids revoked-credential-cids delegations-b64
                     trusted-root-dids operation now-ms tenant-id request-id purpose
                     require-tenant-binding?]
              :or {required-capabilities #{} privileged-capabilities #{}
                   privileged-dids #{} allowed-capabilities #{} revoked-dids #{}
                   revoked-credential-cids #{} delegations-b64 [] trusted-root-dids #{}}}]
  (try
    (let [^js env (.decode dag-cbor (cacao/base64->bytes cacao-b64))
          ^js h (.-h env)
          ^js p (.-p env)
          ^js s (.-s env)
          issuer (.-iss p)
          pub (cid/did-key->ed25519-pub issuer)
          iat-ms (finite-time (.-iat p))
          exp-ms (finite-time (.-exp p))
          now-ms (or now-ms (.getTime (js/Date.)))
          resources (set (vec (.-resources p)))
          allowed-capabilities (if (seq allowed-capabilities)
                                 allowed-capabilities
                                 (into required-capabilities privileged-capabilities))
          capability-resources (set (filter #(str/starts-with? % "kotoba://can/") resources))
          allowed-resources (set (map #(str "kotoba://can/" %) allowed-capabilities))
          tenant-resource (str "kotoba://tenant/" tenant-id)
          allowed-resource-set (cond-> (conj allowed-resources (str "kotoba://graph/" graph))
                                 require-tenant-binding? (conj tenant-resource))
          required-resources (into (cond-> #{(str "kotoba://graph/" graph)}
                                     require-tenant-binding? (conj tenant-resource))
                                   (map #(str "kotoba://can/" %) required-capabilities))
          privileged-resources (set (map #(str "kotoba://can/" %)
                                         privileged-capabilities))
          privileged? (contains? (set privileged-dids) issuer)
          locally-attenuated (if (or privileged? (seq delegations-b64))
                               resources
                               (apply disj resources privileged-resources))
          delegation (when (seq delegations-b64)
                       (authority/verify-chain
                        delegations-b64
                        {:principal issuer :graph graph :now-ms now-ms
                         :tenant-id tenant-id
                         :require-tenant-binding? require-tenant-binding?
                         :trusted-root-dids trusted-root-dids
                         :revoked-credential-cids revoked-credential-cids}))
          effective-resources (if (seq delegations-b64)
                                (when delegation
                                  (set/intersection locally-attenuated
                                                    (:effective-caps delegation)))
                                locally-attenuated)
          payload {:domain (.-domain p) :iss issuer :aud (.-aud p)
                   :version (.-version p) :nonce (.-nonce p)
                   :iat (.-iat p) :exp (.-exp p) :statement (.-statement p)
                   :resources (vec (.-resources p))}
          msg (cacao/cacao-siwe-message payload)
          sig (cacao/base64url->bytes (.-s s))]
      (when (and (= "caip122" (.-t h))
                 (= "EdDSA" (.-t s))
                 (= "kotobase.net" (.-domain p))
                 (= "1" (.-version p))
                 (= audience (.-aud p))
                 (or (nil? purpose) (= purpose (.-statement p)))
                 (not (contains? (set revoked-dids) issuer))
                 (string? (.-nonce p)) (seq (.-nonce p))
                 pub iat-ms exp-ms
                 (<= iat-ms (+ now-ms max-clock-skew-ms))
                 (> exp-ms now-ms)
                 (<= (- exp-ms iat-ms) max-cacao-ttl-ms)
                 (every? allowed-resources capability-resources)
                 (every? allowed-resource-set resources)
                 (or (empty? delegations-b64) delegation)
                 (every? effective-resources required-resources)
                 (.verify ed25519 sig (cid/text->bytes msg) pub))
        {:principal-did issuer
         :audience audience
         :tenant-id tenant-id
         :graph-cid graph
         :operation operation
         :purpose purpose
         :effective-caps effective-resources
         :requested-caps resources
         :attenuated-caps (apply disj resources effective-resources)
         :credential-cids (into [(ipld/cid (cacao/base64->bytes cacao-b64))]
                                (:credential-cids delegation))
         :delegated? (boolean delegation)
         :authority-root (:root-did delegation)
         :issued-at (.-iat p)
         :expires-at (.-exp p)
         :nonce (.-nonce p)
         :request-id request-id}))
    (catch :default _ nil)))

;; ── kg.* write CACAO verify (ai.gftd.apps.kotobase.kg.ingest[_batch]) ───────
;; A SEPARATE, self-contained verifier from verify-cacao-context above --
;; deliberately not a reuse OR a modification of it, so this brand-new kg
;; dispatch path can never perturb the byte-identical behavior of the
;; already-working datomic.transact/fold/read CACAO checks that fn backs
;; (this repo's standing rule: additive-only next to the existing, working
;; datomic.* handlers).

(def ^:private kg-graph-resource-re #"^kotoba://graph/(.+)$")
(def ^:private kg-transact-resources
  "Both spellings of a transact-capability resource this fn accepts as
  proof of a write grant. kotobase-peer.policy/transact-capability is the
  literal string \"kotoba://can/datom:transact\", but the REAL, live kg
  caller mints \"kotoba://op/datom:transact\" instead
  (cloud_itonami/identity_core.cljc's kotobase-resources, following \"the
  kotoba/kotobase convention (kotoba-lang/kagi, cacao README)\" per that
  ns's own docstring) -- a genuine, pre-existing naming split between two
  parts of this codebase family, not invented here. A CACAO still has to
  carry ONE of them, cryptographically signed; accepting both widens which
  literal string counts, it does not drop the requirement."
  #{"kotoba://can/datom:transact" "kotoba://op/datom:transact"})

(defn verify-kg-write-cacao
  "Verify a kg.* WRITE CACAO carried ONLY via the `authorization: CACAO
  <b64>` header (unlike datomic.transact, which reads :cacao_b64 from the
  JSON body) -- kg.ingest/kg.ingest_batch's real, live caller
  (cloud_itonami/net_kotobase.clj's kg-ingest!) sends `Authorization: CACAO
  <cacao>` + `x-kotoba-did: <did>`, no cacao_b64 body field at all, so this
  is a genuinely different wire shape from datomic.transact's, not a
  refactor of it.

  The graph a kg write targets is DERIVED from the CACAO's OWN
  `kotoba://graph/<db-name>` resource, never client-body-supplied
  (kg.ingest has no :graph/:db_name body field at all) -- exactly the
  trust boundary a signed capability resource is FOR. `canonical-graph
  (issuer, db-name)` mirrors datomic.transact's own did+db_name
  derivation, so a kg write for a given (did, db_name) lands in the SAME
  graph a datomic.transact write for that db_name would -- kg/claim/*,
  kg/relation/*, kg/entity/* quads coexist with any ledger data in one
  graph per tenant, no separate kg-graph bookkeeping needed.

  Deliberately does NOT reuse verify-cacao-context's 10-minute max-CACAO-
  age / 1-minute clock-skew windows -- the real live caller mints hour-
  plus TTL session CACAOs (cloud_itonami.net-kotobase/crm-lead-ingest!'s
  default is 1h), which those windows (sized for short browser-session
  tokens) would reject outright. This fn's rigor instead matches `verify-
  cacao`/`verify-cacao-full` above (both already-exported, already-used-
  elsewhere, real-signature-checked, real-expiry-checked verifiers in this
  same file) -- a genuinely less strict but still real level of
  verification already established in this codebase, not invented for
  this path.

  → {:did :db-name :graph} on success, nil on ANY failure (bad signature,
  wrong audience, expired, no transact-capability resource, no graph
  resource, revoked issuer)."
  [cacao-b64 {:keys [audience revoked-dids]}]
  (when (and (string? cacao-b64) (seq cacao-b64))
    (try
      (let [^js env (.decode dag-cbor (cacao/base64->bytes cacao-b64))
            ^js p   (.-p env)
            iss (.-iss p)
            pub (cid/did-key->ed25519-pub iss)
            exp (.-exp p)
            aud (.-aud p)
            resources (set (vec (.-resources p)))
            p-clj {:domain (.-domain p) :iss iss :aud aud :version (.-version p)
                   :nonce (.-nonce p) :iat (.-iat p) :exp exp :statement (.-statement p)
                   :resources (vec (.-resources p))}
            msg (cacao/cacao-siwe-message p-clj)
            sig (cacao/base64url->bytes (.. env -s -s))
            db-name (some #(second (re-matches kg-graph-resource-re %)) resources)]
        (when (and pub (= aud audience) (not (expired? exp))
                   (not (contains? (set revoked-dids) iss))
                   (seq db-name)
                   (some kg-transact-resources resources)
                   (.verify ed25519 sig (cid/text->bytes msg) pub))
          {:did iss :db-name db-name :graph (cid/canonical-graph iss db-name)}))
      (catch :default _ nil))))

(defn- csv-set [env k]
  (let [v (some-> (gobj/get env k) str/trim)]
    (if (str/blank? (or v "")) #{} (set (map str/trim (str/split v #","))))))

(defn- audience [env]
  (some-> (gobj/get env "KOTOBASE_AUDIENCE") str/trim not-empty))

(defn- security-mode [env]
  (case (some-> (gobj/get env "KOTOBASE_SECURITY_MODE") str/trim)
    "public" :public
    "sealed" :sealed
    "legacy-public" :legacy-public
    :private))

(defonce ^:private unwrapped-keyrings (js/WeakMap.))
(defonce ^:private authority-snapshots (js/WeakMap.))

(defn- ensure-authority-snapshot!
  "Load the deployment-trusted revocation/root snapshot once per env when an
  AUTHORITY_REGISTRY service binding is configured. CSV vars remain the
  explicit static/offline fallback."
  [env]
  (if-let [registry (gobj/get env "AUTHORITY_REGISTRY")]
    (if (.has authority-snapshots env)
      (js/Promise.resolve (.get authority-snapshots env))
      (-> (.call (gobj/get registry "snapshot") registry
                 (or (gobj/get env "KOTOBASE_TENANT_ID") "default"))
          (.then (fn [snapshot]
                   (let [value (js->clj snapshot :keywordize-keys true)]
                     (when-not (and (integer? (:version value))
                                    (sequential? (:roots value))
                                    (sequential? (:revoked-dids value))
                                    (sequential? (:revoked-credential-cids value)))
                       (throw (ex-info "authority registry returned malformed snapshot"
                                       {:type :authority-registry-invalid})))
                     (.set authority-snapshots env value)
                     value)))))
    (js/Promise.resolve nil)))

(defn- authority-set [env snapshot-key fallback-var]
  (let [snapshot (.get authority-snapshots env)]
    (if snapshot (set (get snapshot snapshot-key)) (csv-set env fallback-var))))

(defn- ensure-keyring!
  "Unwrap the DEK keyring once per Worker env. Conforming private/sealed
  network startup requires HPKE-wrapped keyring material; raw JSON is allowed
  only behind an explicit test/migration flag."
  [env]
  (let [mode (security-mode env)]
    (if (contains? #{:legacy-public :public} mode)
      (js/Promise.resolve nil)
      (if (.has unwrapped-keyrings env)
        (js/Promise.resolve (.get unwrapped-keyrings env))
        (let [wrapped (gobj/get env "KOTOBASE_WRAPPED_KEYRING_JSON")
              private-key (gobj/get env "KOTOBASE_HPKE_PRIVATE_KEY_B64")
              kms-unwrapper (gobj/get env "KEY_UNWRAPPER")
              raw (gobj/get env "KOTOBASE_KEYRING_JSON")
              allow-raw? (= "1" (gobj/get env "KOTOBASE_ALLOW_UNWRAPPED_KEYRING"))
              tenant (or (gobj/get env "KOTOBASE_TENANT_ID") "default")]
          (cond
            (and kms-unwrapper (seq wrapped))
            (-> (.call (gobj/get kms-unwrapper "unwrap") kms-unwrapper wrapped tenant)
                (.then (fn [raw-keyring]
                         (let [keyring (if (string? raw-keyring)
                                         (js->clj (js/JSON.parse raw-keyring))
                                         (js->clj raw-keyring))]
                           (.set unwrapped-keyrings env keyring)
                           keyring))))
            (and (seq wrapped) (seq private-key))
            (-> (keywrap/unwrap-keyring
                 private-key
                 (js->clj (js/JSON.parse wrapped) :keywordize-keys true)
                 tenant)
                (.then (fn [keyring] (.set unwrapped-keyrings env keyring) keyring)))
            (and allow-raw? (seq raw))
            (let [keyring (js->clj (js/JSON.parse raw))]
              (.set unwrapped-keyrings env keyring)
              (js/Promise.resolve keyring))
            :else
            (js/Promise.reject
             (ex-info "private/sealed requires an HPKE-wrapped keyring"
                      {:type :keywrap-required}))))))))

(defn- crypto-profile
  "Resolve the graph-scoped at-rest profile. private/sealed never downgrade
  when a key binding is missing or malformed."
  ([env graph] (crypto-profile env graph "engine-block"))
  ([env graph block-kind]
  (let [raw-keyring (gobj/get env "KOTOBASE_KEYRING_JSON")
        keyring (or (.get unwrapped-keyrings env)
                    (when (seq raw-keyring) (js->clj (js/JSON.parse raw-keyring))))]
    (crypto/profile {:security-mode (security-mode env)
                     :tenant-id (or (gobj/get env "KOTOBASE_TENANT_ID") "default")
                     :graph graph :block-kind block-kind :schema-version 1
                     :keyring keyring
                     :aead-key-b64 (gobj/get env "KOTOBASE_AEAD_KEY_B64")
                     :blind-key-b64 (gobj/get env "KOTOBASE_BLIND_KEY_B64")}))))

(defn- request-auth
  "Best-effort viewer identity for a READ: the `authorization: CACAO <b64>`
  header or the body's :cacao_b64, verified in full. nil (anonymous) when
  absent/invalid — reads stay open; a graph POLICY decides what an
  anonymous viewer sees (ADR-2607174500)."
  [^js req ^js env body]
  (let [hdr (some-> (.get (.-headers req) "authorization") str)
        b64 (or (when (and hdr (str/starts-with? hdr "CACAO ")) (subs hdr 6))
                (:cacao_b64 body))]
    (when-let [aud (audience env)]
      (when-let [ctx (some-> b64
                             (verify-cacao-context
                              {:audience aud :graph (:graph body) :operation :datom/read
                               :required-capabilities #{"datom:read"}
                               :privileged-capabilities #{"datom:read-protected"}
                               :allowed-capabilities #{"datom:read" "datom:read-protected"}
                               :privileged-dids (csv-set env "KOTOBASE_PROTECTED_READER_DIDS")
                               :revoked-dids (authority-set env :revoked-dids "KOTOBASE_REVOKED_DIDS")
                               :revoked-credential-cids
                               (authority-set env :revoked-credential-cids
                                              "KOTOBASE_REVOKED_CREDENTIAL_CIDS")
                               :delegations-b64 (vec (:delegations_b64 body))
                               :trusted-root-dids
                               (authority-set env :roots "KOTOBASE_AUTHORITY_ROOT_DIDS")
                               :tenant-id (or (gobj/get env "KOTOBASE_TENANT_ID") "default")
                               :require-tenant-binding?
                               (contains? #{:private :sealed} (security-mode env))
                               :request-id (:request_id body)
                               :purpose (:purpose body)}))]
        (let [issuer (:principal-did ctx)
              actor-graph (when (seq (:db_name body))
                            (cid/canonical-graph issuer (:db_name body)))
              shared-reader? (contains? (csv-set env "KOTOBASE_GRAPH_READER_DIDS") issuer)
              authority? (or (= actor-graph (:graph body)) shared-reader? (:delegated? ctx)
                             (contains? #{:legacy-public :public} (security-mode env)))]
          (when authority?
            {:did issuer :resources (:effective-caps ctx) :security-context ctx}))))))

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

(def ^:private max-request-bytes (* 1024 1024))

(defn- read-json-limited
  "Read JSON through a hard byte ceiling before parsing. Rejects unsupported
  content types and oversized streamed bodies without retaining further
  chunks."
  [^js req]
  (let [content-type (or (.get (.-headers req) "content-type") "")
        declared (js/parseInt (or (.get (.-headers req) "content-length") "0") 10)]
    (cond
      (not (str/starts-with? (str/lower-case content-type) "application/json"))
      (js/Promise.reject (ex-info "application/json required" {:type :request/content-type}))
      (> declared max-request-bytes)
      (js/Promise.reject (ex-info "request body too large" {:type :request/too-large}))
      (nil? (.-body req)) (js/Promise.resolve #js {})
      :else
      (let [reader (.getReader (.-body req))]
        (letfn [(step [chunks total]
                  (-> (.read reader)
                      (.then (fn [part]
                               (if (.-done part)
                                 (let [out (js/Uint8Array. total)]
                                   (loop [offset 0 xs chunks]
                                     (when-let [chunk (first xs)]
                                       (.set out chunk offset)
                                       (recur (+ offset (.-length ^js chunk)) (next xs))))
                                   (js/JSON.parse (.decode (js/TextDecoder.) out)))
                                 (let [chunk (.-value part) next-total (+ total (.-length chunk))]
                                   (if (> next-total max-request-bytes)
                                     (do (.cancel reader "request too large")
                                         (throw (ex-info "request body too large"
                                                         {:type :request/too-large})))
                                     (step (conj chunks chunk) next-total))))))))]
          (step [] 0))))))

(defn- prefix
  "Block/head key prefix from KOTOBASE_B2_PREFIX. Read via goog.object/get, NOT
  `(.-KOTOBASE_B2_PREFIX env)`: under :advanced the direct property access is
  renamed and silently reads undefined (same Closure-rename class as the PRF
  extension bug), which collapsed the prefix to \"\" and scattered blocks at the
  bucket root regardless of the configured var."
  [env]
  (let [v (gobj/get env "KOTOBASE_B2_PREFIX")
        base (if (seq v) (str v "/") "")]
    (if (contains? #{:private :sealed} (security-mode env))
      (str base "tenant/"
           (js/encodeURIComponent (or (gobj/get env "KOTOBASE_TENANT_ID") "default")) "/")
      base)))

;; ── read / write orchestration over R2 ───────────────────────────────────────

(defn- run-read
  "Reads (datoms/q/pull/diagHydrateCost/diagCommitCost): trampoline the sync
  handler through R2 blocks. The graph head is read up front (one R2 text
  get) and injected as a constant. `:async-get-fn` is a DIRECT R2 byte fetch
  (bypassing with-blocks entirely) -- only diagHydrateCost/diagCommitCost
  read it (ADR-2607120730 follow-up); every other method ignores it.
  `:put!` is BUFFERED (an in-memory atom, discarded after the response --
  never flushed to R2), matching run-write-attempt's actual :put! during a
  real commit!/fold! (blocks only reach R2 afterward, via flush-blocks-
  and-cas-head!) -- only diagCommitCost uses it, to measure qs/commit!'s
  CPU-only cost as production actually pays it, not inflated by real R2
  write I/O this diagnostic doesn't need (nothing ever reads these blocks
  back, since no head is advanced)."
  [^js bucket pfx method body auth mode crypto-profile]
  (-> (r2/r2-get-text bucket (r2/head-key pfx (:graph body)))
      (.then (fn [head-chain]
               (let [buffer (atom {})]
                 (r2/with-blocks
                   (fn [cid] (r2/cached-block-bytes bucket pfx cid))
                   (fn [sync-get]
                     (h/handle {:get-fn sync-get :head-get (constantly head-chain)
                                :security-mode mode
                                :blind-fn (:blind-fn crypto-profile)
                                :encrypt-fn (:encrypt-fn crypto-profile)
                                :decrypt-fn (:decrypt-fn crypto-profile)
                                :async-get-fn (fn [cid] (r2/cached-block-bytes bucket pfx cid))
                                :put! (fn [cid bytes] (swap! buffer assoc cid bytes))}
                               method body auth))))))))

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
  [^js bucket pfx method body auth crypto-profile]
  (let [buffer (atom {})
        graph  (:graph body)]
    (-> (r2/r2-get-head bucket (r2/head-key pfx graph))
        (.then (fn [{:keys [chain etag]}]
                 (-> (r2/with-blocks
                      (fn [cid] (r2/cached-block-bytes bucket pfx cid))
                      (fn [sync-get]
                        (h/handle {:get-fn (fn [cid] (if (contains? @buffer cid)
                                                        (get @buffer cid)
                                                        (sync-get cid)))
                                   :put! (fn [cid bytes] (swap! buffer assoc cid bytes))
                                   :head-get (constantly chain)
                                   :head-put! (fn [_ _] nil)   ; head CAS'd below
                                   :security-mode (:security-mode auth)
                                   :blind-fn (:blind-fn crypto-profile)
                                   :encrypt-fn (:encrypt-fn crypto-profile)
                                   :decrypt-fn (:decrypt-fn crypto-profile)
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
                                   :cache-put! (fn [k v] (.put bucket (str pfx k) v))
                                   ;; ADR-2607120730 follow-up: do-fold's hydrate
                                   ;; step itself, NOT just what surrounds it
                                   ;; (:max_novelty/:cache-get/:cache-put!), is
                                   ;; O(N^2) over with-blocks -- see do-fold's
                                   ;; docstring. Same direct/unbuffered R2 fetch
                                   ;; as :cache-get, just returning raw bytes.
                                   :async-get-fn (fn [cid] (r2/cached-block-bytes bucket pfx cid))}
                                  method body auth)))
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
  ([bucket pfx method body auth]
   (run-write bucket pfx method body auth crypto/plaintext-profile 1))
  ([bucket pfx method body auth crypto-profile]
   (run-write bucket pfx method body auth crypto-profile 1))
  ([^js bucket pfx method body auth crypto-profile attempt]
   (-> (run-write-attempt bucket pfx method body auth crypto-profile)
       (.then (fn [{:keys [resp cas-ok?]}]
                (cond
                  cas-ok? resp
                  (>= attempt max-head-cas-attempts)
                  {:ok false :error "ConcurrentWriteConflict"
                   :message (str "head CAS lost the race " attempt " times")}
                  :else
                  (-> (delay-ms (min 800 (* 50 attempt)))
                      (.then (fn [_] (run-write bucket pfx method body auth crypto-profile (inc attempt)))))))))))

(defn- digest-hex [value]
  (apply str (map (fn [n] (.padStart (.toString n 16) 2 "0"))
                  (sha256 (cid/text->bytes (pr-str value))))))

(defn idempotency-object-key [pfx principal graph method idempotency-key]
  (str pfx "idempotency/v1/"
       (digest-hex [principal graph method idempotency-key])))

(defn credential-use-object-key [pfx credential-cid]
  (str pfx "replay/v1/" (digest-hex credential-cid)))

(declare run-idempotent-write)

(defn claim-credential-use!
  "Bind a write credential to exactly one request. Network retries with the
  same body and idempotency key are accepted; replaying the credential with a
  different body or key is rejected. The create-if-absent R2 write makes the
  decision atomic across Worker isolates."
  [^js bucket pfx method body auth mode]
  (let [credential-cid (first (get-in auth [:security-context :credential-cids]))]
    (if-not (contains? #{:private :sealed} mode)
      (js/Promise.resolve {:ok true})
      (if (str/blank? (or credential-cid ""))
        (js/Promise.resolve {:ok false :error "CredentialIdentityRequired"})
        (let [k (credential-use-object-key pfx credential-cid)
              record {:version 1
                      :credential-cid credential-cid
                      :principal (:did auth)
                      :graph (:graph body)
                      :operation method
                      :idempotency-key (:idempotency_key body)
                      :request-digest (digest-hex (dissoc body :cacao_b64))}
              encoded (js/JSON.stringify (clj->js record))]
          (-> (r2/r2-put-if-absent bucket k encoded)
              (.then (fn [won?]
                       (if won?
                         {:ok true}
                         (-> (r2/r2-get-text bucket k)
                             (.then (fn [existing]
                                      (if (= record (js->clj (js/JSON.parse existing)
                                                              :keywordize-keys true))
                                        {:ok true :replay true}
                                        {:ok false :error "CredentialReplayConflict"})))))))))))))

(defn run-bound-idempotent-write
  [^js bucket pfx method body auth profile mode]
  (-> (claim-credential-use! bucket pfx method body auth mode)
      (.then (fn [claim]
               (if (:ok claim)
                 (run-idempotent-write bucket pfx method body auth profile mode)
                 claim)))))

(def ^:private idempotency-lease-ms (* 15 60 1000))

(defn run-idempotent-write
  "Durable idempotency claim with lease recovery. Claims and completions use
  R2 ETag/create-if-absent CAS. A crashed pending owner can be reclaimed after
  15 minutes (longer than the configured maximum Worker execution); a live
  owner cannot be stolen."
  [^js bucket pfx method body auth profile mode]
  (let [idempotency-key (:idempotency_key body)]
    (if (str/blank? (or idempotency-key ""))
      (if (contains? #{:private :sealed} mode)
        (js/Promise.resolve {:ok false :error "IdempotencyKeyRequired"})
        (run-write bucket pfx method body auth profile))
      (let [graph (:graph body)
            digest (digest-hex (dissoc body :cacao_b64))
            k (idempotency-object-key pfx (:did auth) graph method idempotency-key)
            pending (fn [base-head]
                      {:version 2 :status "pending" :digest digest
                       :principal (:did auth) :graph graph :operation method
                       :base-head base-head
                       :lease-until (+ (.now js/Date) idempotency-lease-ms)})]
        (letfn [(inspect []
                  (-> (r2/r2-get-head bucket k)
                      (.then (fn [{:keys [chain etag]}]
                               {:etag etag
                                :record (when chain
                                          (js->clj (js/JSON.parse chain)
                                                   :keywordize-keys true))}))))
                (fresh-claim []
                  (-> (r2/r2-get-text bucket (r2/head-key pfx graph))
                      (.then pending)))
                (execute! [claim-etag claim]
                  (-> (run-write bucket pfx method body auth profile)
                      (.then (fn [resp]
                               (-> (.put bucket k
                                         (js/JSON.stringify
                                          (clj->js (assoc claim :status "done"
                                                          :response resp)))
                                         #js {:onlyIf #js {:etagMatches claim-etag}})
                                   (.then (fn [stored]
                                            (if stored resp
                                                {:ok false :error "IdempotencyLeaseLost"}))))))))
                (claim-absent! [claim]
                  (-> (r2/r2-put-if-absent bucket k
                                           (js/JSON.stringify (clj->js claim)))
                      (.then (fn [won?]
                               (if won?
                                 (-> (inspect)
                                     (.then (fn [{:keys [etag]}]
                                              (execute! etag claim))))
                                 (decide!))))))
                (reclaim! [etag claim]
                  (-> (.put bucket k (js/JSON.stringify (clj->js claim))
                            #js {:onlyIf #js {:etagMatches etag}})
                      (.then (fn [^js stored]
                               (if stored
                                 (execute! (.-etag stored) claim)
                                 (decide!))))))
                (decide! []
                  (-> (inspect)
                      (.then (fn [{:keys [record etag]}]
                               (cond
                                 (nil? record) (-> (fresh-claim) (.then claim-absent!))
                                 (not= digest (:digest record))
                                 {:ok false :error "IdempotencyKeyConflict"}
                                 (= "done" (:status record)) (:response record)
                                 (<= (:lease-until record 0) (.now js/Date))
                                 (-> (r2/r2-get-text bucket (r2/head-key pfx graph))
                                     (.then (fn [current-head]
                                              (if (= current-head (:base-head record))
                                                (reclaim! etag (pending current-head))
                                                {:ok false
                                                 :error "IdempotencyRecoveryRequired"
                                                 :base_head (:base-head record)
                                                 :current_head current-head}))))
                                 :else {:ok false :error "IdempotencyRequestInProgress"
                                        :retry_after_ms (- (:lease-until record) (.now js/Date))})))))]
          (decide!))))))

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

(defn emit-audit-receipt
  "Persist one signed+encrypted content-addressed receipt and attach its CID.
  Private/sealed configurations fail closed when the audit signing seed is
  missing; legacy-public remains explicitly non-S5 during migration."
  [^js env ^js bucket pfx method body resp]
  (let [ctx (:_audit-context resp)
        graph (or (:_audit-graph resp) (:graph body)
                  (str "denied-request/" (digest-hex [method (:db_name body)])))
        clean (dissoc resp :_audit-context :_audit-graph)
        seed (gobj/get env "KOTOBASE_AUDIT_SEED_B64")
        mode (security-mode env)]
    (if (and (not (seq seed)) (contains? #{:legacy-public :public} mode))
      (js/Promise.resolve clean)
      (let [profile (crypto-profile env graph "audit-receipt")
            event {"request-id" (or (:request-id ctx) (:request_id body)
                                    (:idempotency_key body))
                   "principal" (:principal-did ctx)
                   "tenant" (or (:tenant-id ctx) (gobj/get env "KOTOBASE_TENANT_ID"))
                   "graph" graph
                   "operation" method
                   "credential-cids" (vec (:credential-cids ctx))
                   "effective-capabilities" (vec (sort (:effective-caps ctx)))
                   "attenuated-capabilities" (vec (sort (:attenuated-caps ctx)))
                   "policy-cid" (:policy-cid clean)
                   "policy-reason" (some-> (:policy-reason clean) str)
                   "key-id" (:key-id profile)
                   "request-digest" (digest-hex (dissoc body :cacao_b64))
                   "previous-head" (:previous_commit clean)
                   "new-head" (:commit clean)
                   "outcome" (cond (:ok clean) "allow"
                                    (:error clean) "deny"
                                    :else "error")
                   "reason" (or (:reason clean) (:error clean))}]
        (-> (audit/create-receipt (audit/signer seed) (:encrypt-fn profile) event)
            (.then (fn [{:keys [cid bytes]}]
                     (-> (r2/r2-put-bytes bucket (r2/block-key pfx cid) bytes)
                         (.then (fn [_] (assoc clean :audit_receipt cid)))))))))))

(defn- audit-ipns-response
  [env bucket pfx method body name ^js response]
  (let [audit-graph (or name "invalid-ipns-name")]
   (-> (.json (.clone response))
      (.then (fn [raw]
               (emit-audit-receipt
                env bucket pfx (str "ipns/" method) (assoc body :graph audit-graph)
                (assoc (js->clj raw :keywordize-keys true)
                       :_audit-graph audit-graph
                       :_audit-context
                       (when-let [principal (:public_key_multibase body)]
                         {:principal-did principal
                          :tenant-id (or (gobj/get env "KOTOBASE_TENANT_ID") "default")
                          :effective-caps #{"kotoba://can/ipns:publish"}})))))
      (.then (fn [audited] (json-response audited (.-status response)))))))

;; ── kg.* dispatch (ai.gftd.apps.kotobase.kg.ingest[_batch], additive) ───────
;; A SEPARATE NSID family from datomic.* -- new cond branch in fetch-handler
;; below, never touching the existing ns-prefix/ipns-ns-prefix branches.
;; Auth is header-carried (verify-kg-write-cacao, above) rather than the
;; body's :cacao_b64 datomic.transact reads, and the graph is derived from
;; the verified CACAO's own capability resource rather than a body
;; :db_name -- both real differences from datomic.transact's wire shape,
;; not an oversight. Reuses run-write/flush-blocks-and-cas-head! unchanged
;; (the same CAS-with-retry commit orchestration transact/fold already
;; share) -- only the auth + graph-derivation front end is new.

(def ^:private kg-ns-prefix (str "/xrpc/" h/kg-ns "."))
(def ^:private kg-methods #{"ingest" "ingest_batch"})

(defn- kg-status [resp]
  (cond (:ok resp) 200
        (= "AccessDenied" (:error resp)) 403
        (= "MethodNotImplemented" (:error resp)) 404
        (= "ConcurrentWriteConflict" (:error resp)) 409
        :else 400))

(defn kg-fetch-handler
  "Handle one `/xrpc/ai.gftd.apps.kotobase.kg.<sub>` request. `sub` is
  \"ingest\"/\"ingest_batch\" (kg-methods) -- an unrecognized sub still
  returns handler.cljc's own MethodNotImplemented shape, not a bare edge
  404, so a caller sees the SAME error contract as an unrecognized
  datomic.* method."
  [^js req ^js env sub]
  (if-not (contains? kg-methods sub)
    (js/Promise.resolve (json-response {:ok false :error "MethodNotImplemented"
                                        :method (str "kg." sub)} 404))
    (-> (ensure-keyring! env)
        (.then (fn [_] (read-json-limited req)))
        (.then (fn [raw]
                 (let [body (js->clj raw :keywordize-keys true)
                       authz (.get (.-headers req) "authorization")
                       cacao-b64 (when (and (string? authz) (re-find #"(?i)^CACAO\s+" authz))
                                   (str/replace authz #"(?i)^CACAO\s+" ""))]
                   (if-let [{:keys [did graph]}
                            (verify-kg-write-cacao
                             cacao-b64
                             {:audience (audience env)
                              :revoked-dids (authority-set env :revoked-dids "KOTOBASE_REVOKED_DIDS")})]
                     (-> (run-write (.-BUCKET env) (prefix env) (str "kg." sub)
                                    (assoc body :graph graph)
                                    {:did did :effective-caps #{policy/transact-capability}
                                     :security-mode (security-mode env)}
                                    (crypto-profile env graph))
                         (.then (fn [resp] (json-response resp (kg-status resp)))))
                     (js/Promise.resolve
                      (json-response {:ok false :error "AuthRequired"
                                      :message "kg write requires a valid Authorization: CACAO <b64> header carrying a transact-capability + graph resource"} 401))))))
        (.catch (fn [^js e]
                  (json-response {:ok false :error "InternalError" :message (.-message e)} 500))))))

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
        (-> (js/Promise.all #js [(ensure-keyring! env)
                                 (ensure-authority-snapshot! env)])
            (.then
             (fn [_]
               (case method
                 "head"
                 (let [name (.get (.-searchParams url) "name")]
                   (-> (run-ipns-head (.-BUCKET env) (prefix env) name)
                       (.then #(audit-ipns-response env (.-BUCKET env) (prefix env)
                                                    method {} name %))))
                 "publish"
                 (-> (read-json-limited req)
                     (.then (fn [raw]
                              (let [body (js->clj raw :keywordize-keys true)]
                                (-> (run-ipns-publish (.-BUCKET env) (prefix env) body)
                                    (.then #(audit-ipns-response env (.-BUCKET env) (prefix env)
                                                                 method body (:name body) %)))))))
                 (js/Promise.resolve
                  (json-response {:ok false :error "MethodNotImplemented" :method method} 404)))))
            (.catch
             (fn [^js e]
               (let [error (case (:type (ex-data e))
                             :request/too-large "RequestTooLarge"
                             :request/content-type "UnsupportedContentType"
                             (if (instance? js/SyntaxError e)
                               "InvalidRequest" "InternalError"))
                     status (case error
                              "RequestTooLarge" 413
                              "UnsupportedContentType" 415
                              "InvalidRequest" 400
                              500)]
                 (-> (emit-audit-receipt
                      env (.-BUCKET env) (prefix env) (str "ipns/" method) {}
                      {:ok false :error error :message (.-message e)
                       :_audit-graph "invalid-ipns-request"})
                     (.then #(json-response % status))
                     (.catch (fn [^js audit-error]
                               (json-response {:ok false :error "AuditUnavailable"
                                               :message (.-message audit-error)} 500)))))))))

      (str/starts-with? path kg-ns-prefix)
      (kg-fetch-handler req env (subs path (count kg-ns-prefix)))

      (not (str/starts-with? path ns-prefix))
      (js/Promise.resolve (json-response {:ok false :error "NotFound"} 404))
      :else
      (let [method (subs path (count ns-prefix))
            audit-body (atom {})
            audit-context (atom nil)
            audit-graph (atom nil)]
        (-> (ensure-keyring! env)
            (.then (fn [_] (read-json-limited req)))
            (.then (fn [raw]
                     (let [body (js->clj raw :keywordize-keys true)]
                       (reset! audit-body body)
                       (case method
                         ("datoms" "q" "pull" "view" "diagHydrateCost" "diagCommitCost")
                         (let [viewer (request-auth req env body)]
                           (reset! audit-context (:security-context viewer))
                           (reset! audit-graph (:graph body))
                           (-> (run-read (.-BUCKET env) (prefix env) method body
                                         viewer (security-mode env)
                                         (crypto-profile env (:graph body)))
                               (.then #(assoc % :_audit-context (:security-context viewer)))))
                         "transact"
                         ;; kotobase transact sends :db_name (+ cacao), NOT :graph —
                         ;; the graph is DERIVED as canonical-graph(issuer, db_name)
                         ;; so a write always lands on the issuer's own graph.
                         (let [graph-for (fn [did] (cid/canonical-graph did (:db_name body)))
                               preliminary (some-> (:cacao_b64 body) verify-cacao-full)
                               graph (some-> preliminary :did graph-for)
                               context (when graph
                                         (verify-cacao-context
                                          (:cacao_b64 body)
                                          {:audience (audience env) :graph graph
                                           :operation :datom/transact
                                           :required-capabilities #{"datom:transact" "tx:create"}
                                           :privileged-capabilities #{"datom:policy-admin"}
                                           :allowed-capabilities #{"datom:transact" "tx:create"
                                                                   "datom:policy-admin"}
                                           :privileged-dids (csv-set env "KOTOBASE_POLICY_ADMIN_DIDS")
                                           :revoked-dids
                                           (authority-set env :revoked-dids "KOTOBASE_REVOKED_DIDS")
                                           :tenant-id (or (gobj/get env "KOTOBASE_TENANT_ID") "default")
                                           :require-tenant-binding?
                                           (contains? #{:private :sealed} (security-mode env))
                                           :request-id (:idempotency_key body)
                                           :purpose (:purpose body)}))
                               issuer (:principal-did context)]
                           (reset! audit-context context)
                           (reset! audit-graph graph)
                           (if-not (authorized? env issuer)
                             (js/Promise.resolve {:ok false :error "AuthRequired"
                                                  :_audit-context context :_audit-graph graph})
                             (-> (run-bound-idempotent-write
                                  (.-BUCKET env) (prefix env) "transact"
                                  (assoc body :graph graph)
                                  {:did issuer
                                   :effective-caps (:effective-caps context)
                                   :purpose (:purpose context)
                                   :security-context context
                                   :security-mode (security-mode env)}
                                  (crypto-profile env graph) (security-mode env))
                                 (.then #(assoc % :_audit-context context :_audit-graph graph)))))
                         "fold"
                         ;; Maintenance op (ADR-2607032430 D1): an authorized caller
                         ;; (cron/ops, not necessarily the graph owner — one operator
                         ;; identity may fold many actors' graphs) names the :graph
                         ;; directly, unlike transact's derived graph.
                         (let [context (verify-cacao-context
                                        (:cacao_b64 body)
                                        {:audience (audience env) :graph (:graph body)
                                         :operation :datom/fold
                                         :required-capabilities #{"datom:fold"}
                                         :privileged-capabilities #{"datom:fold"}
                                         :allowed-capabilities #{"datom:fold"}
                                         :privileged-dids (csv-set env "KOTOBASE_MAINTAINER_DIDS")
                                         :revoked-dids
                                         (authority-set env :revoked-dids "KOTOBASE_REVOKED_DIDS")
                                         :tenant-id (or (gobj/get env "KOTOBASE_TENANT_ID") "default")
                                         :require-tenant-binding?
                                         (contains? #{:private :sealed} (security-mode env))
                                         :request-id (:idempotency_key body)
                                         :purpose (:purpose body)})
                               issuer (:principal-did context)]
                           (reset! audit-context context)
                           (reset! audit-graph (:graph body))
                           (if-not (authorized? env issuer)
                             (js/Promise.resolve {:ok false :error "AuthRequired"
                                                  :_audit-context context})
                             (-> (run-bound-idempotent-write
                                  (.-BUCKET env) (prefix env) "fold" body
                                  {:did issuer
                                   :effective-caps (:effective-caps context)
                                   :security-context context
                                   :security-mode (security-mode env)}
                                  (crypto-profile env (:graph body)) (security-mode env))
                                 (.then #(assoc % :_audit-context context)))))
                         (js/Promise.resolve {:ok false :error "MethodNotImplemented" :method method})))))
            (.catch (fn [^js e]
                      {:ok false
                       :error (case (:type (ex-data e))
                                :request/too-large "RequestTooLarge"
                                :request/content-type "UnsupportedContentType"
                                (if (instance? js/SyntaxError e)
                                  "InvalidRequest" "InternalError"))
                       :message (.-message e)
                       :_audit-context @audit-context :_audit-graph @audit-graph}))
            (.then (fn [resp]
                     (emit-audit-receipt env (.-BUCKET env) (prefix env)
                                         method
                                         @audit-body
                                         resp)))
            (.then (fn [resp]
                     (json-response resp
                                    (case (:error resp)
                                      "AuthRequired" 403
                                      "AccessDenied" 403
                                      "IdempotencyKeyRequired" 400
                                      "IdempotencyKeyConflict" 409
                                      "IdempotencyRequestInProgress" 409
                                      "IdempotencyRecoveryRequired" 409
                                      "CredentialIdentityRequired" 400
                                      "CredentialReplayConflict" 409
                                      "MethodNotImplemented" 404
                                      "RequestTooLarge" 413
                                      "UnsupportedContentType" 415
                                      "InvalidRequest" 400
                                      200))))
            (.catch (fn [^js e]
                      (json-response {:ok false :error "AuditUnavailable"
                                      :message (.-message e)} 500))))))))

(def handler #js {:fetch fetch-handler})
