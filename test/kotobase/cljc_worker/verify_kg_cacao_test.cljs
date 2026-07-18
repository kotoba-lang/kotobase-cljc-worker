(ns kotobase.cljc-worker.verify-kg-cacao-test
  "Coverage for verify-kg-write-cacao (ai.gftd.apps.kotobase.kg.ingest[_batch]'s
  header-carried CACAO check) and the kg.* fetch-handler route end to end.
  Deliberately hand-mints CACAOs with EXPLICIT :resources (kotobase.cacao/
  mint-cacao's own :capability option always produces a `kotoba://can/...`
  resource, but the real live kg caller mints `kotoba://op/...` instead --
  see verify-kg-write-cacao's own docstring), matching verify_cacao_test.
  cljs's own delegation-grant/mint-with-exp precedent for testing a shape
  mint-cacao itself cannot produce."
  (:require [cljs.test :refer [deftest is testing async]]
            [kotobase.cljc-worker.worker :as w]
            [kotobase.cacao :as cacao]
            [kotobase.cid :as cid]
            ["@ipld/dag-cbor" :as dag-cbor]
            ["@noble/curves/ed25519.js" :refer [ed25519]]))

(def seed (js/Uint8Array.from (clj->js (range 32))))
(def other-seed (js/Uint8Array.from (clj->js (range 32 64))))

(defn- mint-kg-cacao
  "Hand-mint a CACAO with explicit :resources (unlike kotobase.cacao/mint-
  cacao, which always prefixes a single capability with kotoba://can/)."
  [{:keys [secret-key aud resources exp-ms now-ms]
    :or {secret-key seed aud "did:web:kotobase.aozora.app"
         now-ms (.getTime (js/Date.))}}]
  (let [pub (.getPublicKey ed25519 secret-key)
        did (cid/did-key-from-ed25519-pub pub)
        p {:domain "kotobase.net" :iss did :aud aud :version "1"
           :nonce "kg-test-nonce" :iat (.toISOString (js/Date. now-ms))
           :exp (.toISOString (js/Date. (or exp-ms (+ now-ms 3600000))))
           :statement nil :resources resources}
        msg (cacao/cacao-siwe-message p)
        sig (.sign ed25519 (cid/text->bytes msg) secret-key)
        cacao-js #js {:h #js {:t "caip122"} :p (clj->js p)
                     :s #js {:t "EdDSA" :s (cacao/bytes->base64url sig)}}]
    {:cacao-b64 (cacao/bytes->base64 (.encode dag-cbor cacao-js)) :did did}))

(def aud "did:web:kotobase.aozora.app")

(deftest accepts-the-real-live-callers-op-prefixed-resources
  ;; cloud_itonami/identity_core.cljc's kotobase-resources: op/datom:read +
  ;; op/datom:transact + graph/<db-name> -- NOT kotoba://can/...
  (let [{:keys [cacao-b64 did]}
        (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:read"
                                             "kotoba://op/datom:transact"
                                             "kotoba://graph/itonami/crm"]})
        ctx (w/verify-kg-write-cacao cacao-b64 {:audience aud})]
    (is (some? ctx))
    (is (= did (:did ctx)))
    (is (= "itonami/crm" (:db-name ctx)))
    (is (= (cid/canonical-graph did "itonami/crm") (:graph ctx))
        "graph is derived the SAME way datomic.transact derives it: canonical-graph(issuer, db-name)")))

(deftest accepts-the-can-prefixed-spelling-too
  (let [{:keys [cacao-b64]}
        (mint-kg-cacao {:aud aud :resources ["kotoba://can/datom:transact"
                                             "kotoba://graph/some/db"]})]
    (is (some? (w/verify-kg-write-cacao cacao-b64 {:audience aud})))))

(deftest rejects-a-cacao-with-no-transact-capability-resource-at-all
  (let [{:keys [cacao-b64]}
        (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:read"
                                             "kotoba://graph/itonami/crm"]})]
    (is (nil? (w/verify-kg-write-cacao cacao-b64 {:audience aud})))))

(deftest rejects-a-cacao-with-no-graph-resource
  (let [{:keys [cacao-b64]}
        (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:transact"]})]
    (is (nil? (w/verify-kg-write-cacao cacao-b64 {:audience aud})))))

(deftest rejects-wrong-audience
  (let [{:keys [cacao-b64]}
        (mint-kg-cacao {:aud "did:web:someone-else"
                        :resources ["kotoba://op/datom:transact" "kotoba://graph/g"]})]
    (is (nil? (w/verify-kg-write-cacao cacao-b64 {:audience aud})))))

(deftest rejects-an-expired-cacao
  (let [{:keys [cacao-b64]}
        (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:transact" "kotoba://graph/g"]
                        :now-ms (- (.getTime (js/Date.)) 7200000)
                        :exp-ms (- (.getTime (js/Date.)) 3600000)})]
    (is (nil? (w/verify-kg-write-cacao cacao-b64 {:audience aud})))))

(deftest rejects-an-hour-plus-ttl-cacao-the-real-caller-actually-mints
  ;; The whole reason this fn does NOT reuse verify-cacao-context's 10-
  ;; minute max-age window: crm-lead-ingest!'s real default TTL is 1h.
  (let [now (.getTime (js/Date.))
        {:keys [cacao-b64]}
        (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:transact" "kotoba://graph/g"]
                        :now-ms now :exp-ms (+ now 3600000)})]
    (is (some? (w/verify-kg-write-cacao cacao-b64 {:audience aud}))
        "a 1h-TTL CACAO (unexpired) must be ACCEPTED, not rejected on age alone")))

(deftest rejects-a-revoked-issuer
  (let [{:keys [cacao-b64 did]}
        (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:transact" "kotoba://graph/g"]})]
    (is (nil? (w/verify-kg-write-cacao cacao-b64 {:audience aud :revoked-dids #{did}})))))

(deftest rejects-a-tampered-signature
  ;; Flip a character in the MIDDLE of the base64 envelope -- the payload
  ;; (long did:key/ISO-date/resource-URI strings) dominates the byte
  ;; stream, so a middle mutation reliably lands inside it, changing the
  ;; SIWE message the signature was computed over (or corrupting the CBOR
  ;; structure outright, caught by this fn's own try/catch) -- either way
  ;; a genuinely different, no-longer-valid CACAO. (A tail mutation isn't
  ;; reliable: DAG-CBOR's canonical/sorted map-key ordering can put a
  ;; short, ignored field like {:t \"EdDSA\"} after the signature bytes,
  ;; so corrupting only the last few chars can miss the signature
  ;; entirely -- confirmed empirically, not theoretical.)
  (let [{:keys [cacao-b64]}
        (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:transact" "kotoba://graph/g"]})
        mid (quot (count cacao-b64) 2)
        flipped (if (= \A (nth cacao-b64 mid)) \B \A)
        forged (str (subs cacao-b64 0 mid) flipped (subs cacao-b64 (inc mid)))]
    (is (nil? (w/verify-kg-write-cacao forged {:audience aud})))))

(deftest sanity-a-second-signer-mints-an-independently-valid-cacao
  ;; sanity check on the helper itself, not a security property: a
  ;; different secret-key -> different (self-consistent) issuer DID, still
  ;; verifies fine against its OWN signature.
  (let [{:keys [cacao-b64]}
        (mint-kg-cacao {:secret-key other-seed :aud aud
                        :resources ["kotoba://op/datom:transact" "kotoba://graph/g"]})]
    (is (some? (w/verify-kg-write-cacao cacao-b64 {:audience aud})))))

;; ── end to end: POST /xrpc/ai.gftd.apps.kotobase.kg.ingest ──────────────────

(defn- fake-bucket []
  (let [store (atom {}) etag-seq (atom 0)]
    #js {:get (fn [k]
                (js/Promise.resolve
                 (when-let [{:keys [value etag]} (get @store k)]
                   #js {:text (fn [] (js/Promise.resolve value))
                        :arrayBuffer (fn [] (js/Promise.resolve (js/Uint8Array.from value)))
                        :etag etag})))
         :put (fn [k v ^js opts]
                (js/Promise.resolve
                 (let [only-if (some-> opts .-onlyIf)
                       required (some-> only-if .-etagMatches)
                       absent? (and (instance? js/Headers only-if)
                                    (= "*" (.get only-if "if-none-match")))]
                   (if (or (and absent? (contains? @store k))
                           (and (some? required) (not= required (:etag (get @store k)))))
                     nil
                     (let [new-etag (str "etag-" (swap! etag-seq inc))]
                       (swap! store assoc k {:value v :etag new-etag})
                       #js {:etag new-etag})))))
         :__store store}))

(deftest kg-ingest-post-route-commits-a-real-write-end-to-end
  (async done
    (let [bucket (fake-bucket)
          env #js {:BUCKET bucket :KOTOBASE_AUDIENCE aud :KOTOBASE_SECURITY_MODE "legacy-public"}
          {:keys [cacao-b64 did]}
          (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:transact"
                                               "kotoba://graph/itonami/crm"]})
          req (js/Request.
               "https://example.test/xrpc/ai.gftd.apps.kotobase.kg.ingest"
               #js {:method "POST"
                    :headers #js {"content-type" "application/json"
                                  "authorization" (str "CACAO " cacao-b64)}
                    :body (js/JSON.stringify
                           #js {:id "crm.lead:e2e" :type "crm.lead" :labelEn "selftest"
                                :claims #js [#js {:pred "crm.lead/source" :value "e2e-test"}]
                                :relations #js []
                                :tenant_did did})})]
      (-> (w/fetch-handler req env)
          (.then (fn [^js resp]
                   (is (= 200 (.-status resp)))
                   (.json resp)))
          (.then (fn [^js body]
                   (is (true? (.-ok body)))
                   (is (string? (.-subjectCid body)))
                   (is (= 3 (.-quadCount body)))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest kg-ingest-post-route-rejects-a-missing-cacao
  (async done
    (let [env #js {:BUCKET (fake-bucket) :KOTOBASE_AUDIENCE aud :KOTOBASE_SECURITY_MODE "legacy-public"}
          req (js/Request.
               "https://example.test/xrpc/ai.gftd.apps.kotobase.kg.ingest"
               #js {:method "POST"
                    :headers #js {"content-type" "application/json"}
                    :body (js/JSON.stringify #js {:id "e1" :type "x"})})]
      (-> (w/fetch-handler req env)
          (.then (fn [^js resp]
                   (is (= 401 (.-status resp)))
                   (.json resp)))
          (.then (fn [^js body]
                   (is (= "AuthRequired" (.-error body)))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest kg-ingest-batch-post-route-works-too
  (async done
    (let [bucket (fake-bucket)
          env #js {:BUCKET bucket :KOTOBASE_AUDIENCE aud :KOTOBASE_SECURITY_MODE "legacy-public"}
          {:keys [cacao-b64]}
          (mint-kg-cacao {:aud aud :resources ["kotoba://op/datom:transact"
                                               "kotoba://graph/itonami/crm"]})
          req (js/Request.
               "https://example.test/xrpc/ai.gftd.apps.kotobase.kg.ingest_batch"
               #js {:method "POST"
                    :headers #js {"content-type" "application/json"
                                  "authorization" (str "CACAO " cacao-b64)}
                    :body (js/JSON.stringify
                           #js {:entities #js [#js {:id "e1" :type "x"}
                                               #js {:id "e2" :type "x"}]})})]
      (-> (w/fetch-handler req env)
          (.then (fn [^js resp]
                   (is (= 200 (.-status resp)))
                   (.json resp)))
          (.then (fn [^js body]
                   (is (true? (.-ok body)))
                   (is (= 2 (.-ingested body)))
                   (is (= 2 (.-length (.-subjectCids body))))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest kg-unknown-sub-method-returns-methodnotimplemented-not-a-bare-404
  (async done
    (let [env #js {:BUCKET (fake-bucket) :KOTOBASE_AUDIENCE aud :KOTOBASE_SECURITY_MODE "legacy-public"}
          req (js/Request.
               "https://example.test/xrpc/ai.gftd.apps.kotobase.kg.frobnicate"
               #js {:method "POST" :headers #js {"content-type" "application/json"}
                    :body "{}"})]
      (-> (w/fetch-handler req env)
          (.then (fn [^js resp]
                   (is (= 404 (.-status resp)))
                   (.json resp)))
          (.then (fn [^js body]
                   (is (= "MethodNotImplemented" (.-error body)))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))
