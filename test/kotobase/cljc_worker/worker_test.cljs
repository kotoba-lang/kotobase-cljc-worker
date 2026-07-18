(ns kotobase.cljc-worker.worker-test
  "Regression coverage for INCIDENT 2607032800 (\"worker commit!
  null.length\"): do-transact's own novelty_size re-reads the chain-cid it
  JUST committed, before run-write-attempt ever flushes it to R2. Without a
  read-your-own-writes merge of the write buffer over the with-blocks
  trampoline, that read is a genuine miss against R2 (the block only exists
  in the in-memory buffer), the trampoline caches the miss AS nil, and the
  retry's sync-get returns nil WITHOUT throwing — ipld/decode nil then
  crashes with `Cannot read properties of null (reading 'length')`,
  swallowed by handler.cljc's own try/catch into a normal-looking `{:ok
  false :error \"InternalError\" ...}` response. handler_test.cljc's
  mem-store fixture shares ONE atom between :get-fn and :put!, so it never
  exercises this at all — only a genuinely async store (a real R2 bucket,
  or this fake one) does."
  (:require [clojure.string :as str]
            [cljs.test :refer [deftest is testing async]]
            [kotobase.cacao :as cacao]
            [kotobase.server.security.audit :as audit]
            [kotobase.server.security.crypto :as crypto]
            [kotobase.server.security.keywrap :as keywrap]
            [kotobase.cljc-worker.r2 :as r2]
            [kotobase.cljc-worker.worker :as w]))

(defn- key64 [offset]
  (cacao/bytes->base64
   (js/Uint8Array.from (clj->js (map #(+ offset %) (range 32))))))

;; Same fidelity contract as r2-test's make-fake-bucket (this repo's own
;; precedent for mocking R2 without a live Cloudflare binding): async
;; .get/.put, minted etags, unconditional put on a nil onlyIf.
;;
;; Optional `store` arg (default: a fresh atom) lets a caller keep a
;; reference to the underlying key/value map to inspect after a call --
;; existing 0-arg call sites are unaffected.
(defn- make-fake-bucket
  ([] (make-fake-bucket (atom {})))
  ([store]
   (let [etag-seq (atom 0)]
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
                            (and (some? required)
                                 (not= required (:etag (get @store k)))))
                      nil
                      (let [new-etag (str "etag-" (swap! etag-seq inc))]
                        (swap! store assoc k {:value v :etag new-etag})
                        #js {:etag new-etag})))))
          :__store store})))

(deftest genesis-transact-against-a-real-async-bucket-succeeds
  (async done
    (-> (w/run-write (make-fake-bucket) "" "transact"
                     {:graph "g" :tx_edn "[{:db/id \"e1\" :yoro.post/uri \"at://a/p1\"}]"}
                     nil)
        (.then (fn [resp]
                 (testing "do-transact's own novelty_size re-read of its just-committed chain must not crash"
                   (is (:ok resp) (str "resp: " (pr-str resp)))
                   (is (string? (:commit resp)))
                   (is (= 1 (:novelty_size resp))))
                 (done)))
        (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done))))))

(deftest idempotency-replays-result-and-rejects-key-reuse
  (async done
    (let [bucket (make-fake-bucket)
          auth {:did "did:key:test" :security-mode :legacy-public
                :effective-caps #{"kotoba://can/datom:transact"
                                  "kotoba://can/datom:policy-admin"}}
          body {:graph "idem-g" :idempotency_key "request-1"
                :tx_edn "[{:db/id \"e1\" :n 1}]"}]
      (-> (w/run-idempotent-write bucket "" "transact" body auth
                                  crypto/plaintext-profile :legacy-public)
          (.then (fn [first-resp]
                   (is (:ok first-resp))
                   (-> (w/run-idempotent-write bucket "" "transact" body auth
                                               crypto/plaintext-profile :legacy-public)
                       (.then (fn [again]
                                (is (= first-resp again) "same request returns stored outcome"))))))
          (.then (fn [_]
                   (w/run-idempotent-write bucket "" "transact"
                                           (assoc body :tx_edn "[{:db/id \"e2\" :n 2}]")
                                           auth crypto/plaintext-profile :legacy-public)))
          (.then (fn [conflict]
                   (is (= "IdempotencyKeyConflict" (:error conflict)))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest private-write-credential-is-bound-to-one-request
  (async done
    (let [bucket (make-fake-bucket)
          auth {:did "did:key:test"
                :security-context {:credential-cids ["bafy-write-credential"]}}
          body {:graph "replay-g" :idempotency_key "request-1"
                :tx_edn "[{:db/id \"e1\" :n 1}]"}]
      (-> (w/claim-credential-use! bucket "tenant/t/" "transact" body auth :private)
          (.then (fn [first-claim]
                   (is (:ok first-claim))
                   (w/claim-credential-use! bucket "tenant/t/" "transact" body auth :private)))
          (.then (fn [retry-claim]
                   (is (:ok retry-claim))
                   (is (:replay retry-claim) "byte-equivalent network retry is allowed")
                   (w/claim-credential-use!
                    bucket "tenant/t/" "transact"
                    (assoc body :idempotency_key "request-2" :tx_edn "[{:db/id \"e2\" :n 2}]")
                    auth :private)))
          (.then (fn [conflict]
                   (is (= "CredentialReplayConflict" (:error conflict)))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest expired-idempotency-lease-recovers-only-when-head-is-unchanged
  (async done
    (let [bucket (make-fake-bucket)
          auth {:did "did:key:test" :security-mode :legacy-public
                :effective-caps #{"kotoba://can/datom:transact"
                                  "kotoba://can/datom:policy-admin"}}
          body {:graph "lease-g" :idempotency_key "lease-1"
                :tx_edn "[{:db/id \"e1\" :n 1}]"}
          k (w/idempotency-object-key "" (:did auth) (:graph body) "transact"
                                      (:idempotency_key body))
          store (.-__store ^js bucket)]
      ;; Seed an expired claim. Its digest is learned by letting a first call
      ;; create/complete, then rewriting only status/lease/base-head while
      ;; preserving the production-computed digest.
      (-> (w/run-idempotent-write bucket "" "transact" body auth
                                  crypto/plaintext-profile :legacy-public)
          (.then (fn [_]
                   (let [{:keys [value etag]} (get @store k)
                         record (js->clj (js/JSON.parse value) :keywordize-keys true)
                         current-head (:value (get @store "heads/lease-g"))
                         expired (assoc record :status "pending" :lease-until 0
                                               :base-head current-head)]
                     (swap! store assoc k {:value (js/JSON.stringify (clj->js expired))
                                           :etag etag})
                     (w/run-idempotent-write bucket "" "transact" body auth
                                             crypto/plaintext-profile :legacy-public))))
          (.then (fn [recovered]
                   (is (:ok recovered) "unchanged base head permits safe lease recovery")
                   (let [{:keys [value etag]} (get @store k)
                         record (js->clj (js/JSON.parse value) :keywordize-keys true)
                         expired (assoc record :status "pending" :lease-until 0
                                               :base-head "definitely-another-head")]
                     (swap! store assoc k {:value (js/JSON.stringify (clj->js expired))
                                           :etag etag})
                     (w/run-idempotent-write bucket "" "transact" body auth
                                             crypto/plaintext-profile :legacy-public))))
          (.then (fn [ambiguous]
                   (is (= "IdempotencyRecoveryRequired" (:error ambiguous))
                       "changed head is never blindly replayed")
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest private-response-emits-verifiable-encrypted-audit-receipt
  (async done
    (let [bucket (make-fake-bucket)
          keyring {"active" "k1"
                   "keys" {"k1" {"aead" (key64 32) "blind" (key64 64)}}}
          env #js {:KOTOBASE_SECURITY_MODE "private"
                   :KOTOBASE_TENANT_ID "tenant-a"
                   :KOTOBASE_KEYRING_JSON (js/JSON.stringify (clj->js keyring))
                   :KOTOBASE_AUDIT_SEED_B64 (key64 0)}
          body {:graph "audit-g" :idempotency_key "req-1" :tx_edn "[]"}
          context {:principal-did "did:key:actor" :tenant-id "tenant-a"
                   :effective-caps #{"kotoba://can/datom:transact"}
                   :attenuated-caps #{} :credential-cids ["bafycredential"]}
          profile (crypto/profile {:security-mode :private :tenant-id "tenant-a"
                                   :graph "audit-g" :block-kind "audit-receipt"
                                   :keyring keyring})]
      (-> (w/emit-audit-receipt env bucket "" "transact" body
                                {:ok true :commit "bafynew"
                                 :_audit-context context})
          (.then (fn [resp]
                   (let [receipt (:audit_receipt resp)
                         stored (:value (get @(.-__store ^js bucket)
                                             (r2/block-key "" receipt)))]
                     (is (string? receipt))
                     (is (some? stored))
                     (audit/verify-receipt receipt stored (:decrypt-fn profile)
                                           (:did (audit/signer (key64 0)))))))
          (.then (fn [signed]
                   (is (= "transact" (get signed "operation")))
                   (is (= "allow" (get signed "outcome")))
                   (w/emit-audit-receipt env bucket "" "transact" body
                                         {:ok false :error "AccessDenied"
                                          :reason "attribute-denied"
                                          :_audit-context context})))
          (.then (fn [resp]
                   (let [receipt (:audit_receipt resp)
                         stored (:value (get @(.-__store ^js bucket)
                                             (r2/block-key "" receipt)))]
                     (audit/verify-receipt receipt stored (:decrypt-fn profile)
                                           (:did (audit/signer (key64 0)))))))
          (.then (fn [signed]
                   (is (= "deny" (get signed "outcome")))
                   (is (= "attribute-denied" (get signed "reason")))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest private-fetch-unwraps-hpke-keyring-and-returns-audit-cid
  (async done
    (let [bucket (make-fake-bucket)
          keyring {"active" "k1"
                   "keys" {"k1" {"aead" (key64 32) "blind" (key64 64)}}}]
      (-> (keywrap/generate-recipient-keypair)
          (.then (fn [{:keys [public-key-b64 private-key-b64]}]
                   (-> (keywrap/wrap-keyring public-key-b64 keyring "tenant-a")
                       (.then (fn [wrapped]
                                (let [env #js {:BUCKET bucket
                                               :KOTOBASE_SECURITY_MODE "private"
                                               :KOTOBASE_TENANT_ID "tenant-a"
                                               :KOTOBASE_WRAPPED_KEYRING_JSON
                                               (js/JSON.stringify (clj->js wrapped))
                                               :KOTOBASE_HPKE_PRIVATE_KEY_B64 private-key-b64
                                               :KOTOBASE_AUDIT_SEED_B64 (key64 0)
                                               :KOTOBASE_AUDIENCE "did:web:kotobase.test"}
                                      req (js/Request.
                                           "https://example.test/xrpc/ai.gftd.apps.kotobase.datomic.datoms"
                                           #js {:method "POST"
                                                :headers #js {"content-type" "application/json"}
                                                :body (js/JSON.stringify
                                                       #js {:graph "g" :index "eavt"
                                                            :components_edn #js []})})]
                                  (w/fetch-handler req env)))))))
          (.then (fn [response]
                   (is (= 200 (.-status response)))
                   (.json response)))
          (.then (fn [^js body]
                   (is (string? (.-audit_receipt body)))
                   (is (array? (.-datoms body)))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest transport-gate-rejects-oversized-and-non-json-requests
  (async done
    (let [env #js {:BUCKET (make-fake-bucket)
                   :KOTOBASE_SECURITY_MODE "legacy-public"
                   :KOTOBASE_AUDIENCE "did:web:test"}
          url "https://example.test/xrpc/ai.gftd.apps.kotobase.datomic.datoms"
          oversized (js/Request. url #js {:method "POST"
                                          :headers #js {"content-type" "application/json"
                                                        "content-length" "1048577"}
                                          :body "{}"})
          wrong-type (js/Request. url #js {:method "POST"
                                           :headers #js {"content-type" "text/plain"}
                                           :body "{}"})]
      (-> (w/fetch-handler oversized env)
          (.then (fn [^js response]
                   (is (= 413 (.-status response)))
                   (w/fetch-handler wrong-type env)))
          (.then (fn [^js response]
                   (is (= 415 (.-status response)))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest transact-then-fold-against-a-real-async-bucket-both-succeed
  (async done
    (let [bucket (make-fake-bucket)]
      (-> (w/run-write bucket "" "transact"
                       {:graph "g2" :tx_edn "[{:db/id \"e1\" :yoro.post/uri \"at://a/p1\"}]"}
                       nil)
          (.then (fn [_] (w/run-write bucket "" "fold" {:graph "g2"} nil)))
          (.then (fn [resp]
                   (testing "do-fold reading back its own fold!-written blocks must not crash either"
                     (is (:ok resp) (str "resp: " (pr-str resp)))
                     (is (:folded resp)))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest fold-against-a-real-async-bucket-populates-the-memoized-hydration-cache
  ;; ADR-2607120730 Part 1: proves the R2 adapter (:cache-get/:cache-put! in
  ;; run-write-attempt's store -- kotobase.cljc-worker.r2/r2-get-text plus a
  ;; direct .put, NOT threaded through the buffered end-of-request flush) is
  ;; wired correctly end-to-end through the REAL run-write/do-fold path, not
  ;; just at the pure-handler layer (handler_test.cljc) or the engine layer
  ;; (kotobase-peer's own cache-hit-skips-decrypt tests).
  (async done
    (let [store (atom {})
          bucket (make-fake-bucket store)
          pfx "kotobase/cljc-v3/"
          tx (fn [n] (str "[{:db/id \"e" n "\" :yoro.post/uri \"at://a/p" n "\"}]"))]
      (-> (w/run-write bucket pfx "transact" {:graph "g4" :tx_edn (tx 1)} nil)
          (.then (fn [_] (w/run-write bucket pfx "fold" {:graph "g4"} nil))) ; warm-up: first indexed snapshot
          (.then (fn [_] (w/run-write bucket pfx "transact" {:graph "g4" :tx_edn (tx 2)} nil)))
          (.then (fn [_] (w/run-write bucket pfx "fold" {:graph "g4"} nil))) ; the fold under test
          (.then (fn [resp]
                   (is (:ok resp) (str "resp: " (pr-str resp)))
                   (is (:folded resp))
                   (is (some #(str/starts-with? % (str pfx "hydrate-cache/v1/")) (keys @store))
                       "cache-put! actually wrote a hydrate-cache entry to the bucket, under the configured prefix")
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))
