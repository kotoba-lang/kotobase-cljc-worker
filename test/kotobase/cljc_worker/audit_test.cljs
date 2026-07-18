(ns kotobase.cljc-worker.audit-test
  (:require [cljs.test :refer [deftest is async]]
            [kotobase.cacao :as cacao]
            [kotobase.server.security.audit :as audit]
            [kotobase.server.security.crypto :as crypto]))

(defn- key64 [offset]
  (cacao/bytes->base64
   (js/Uint8Array.from (clj->js (map #(+ offset %) (range 32))))))

(deftest receipt-is-signed-encrypted-addressed-and-tamper-evident
  (async done
    (let [signer (audit/signer (key64 0))
          profile (crypto/profile {:security-mode :private :tenant-id "t"
                                   :graph "g" :block-kind "audit-receipt"
                                   :aead-key-b64 (key64 32) :blind-key-b64 (key64 64)})
          event {"operation" "transact" "outcome" "allow"
                 "request-digest" "abc"}]
      (-> (audit/create-receipt signer (:encrypt-fn profile) event)
          (.then (fn [{:keys [cid bytes]}]
                   (-> (audit/verify-receipt cid bytes (:decrypt-fn profile) (:did signer))
                       (.then (fn [verified]
                                (is (= "allow" (get verified "outcome")))
                                (let [tampered (.slice bytes)]
                                  (aset tampered (dec (.-length tampered))
                                        (bit-xor 1 (aget tampered (dec (.-length tampered)))))
                                  (try
                                    (audit/verify-receipt cid tampered (:decrypt-fn profile) (:did signer))
                                    (is false "tampered CID must throw")
                                    (catch :default _ (is true)))))))))
          (.then (fn [_] (done)))
          (.catch (fn [e] (is false (.-message e)) (done)))))))

(deftest receipt-rejects-an-unpinned-or-wrong-signer
  (async done
    (let [signer (audit/signer (key64 0))
          other (audit/signer (key64 1))
          profile (crypto/profile {:security-mode :private :tenant-id "t"
                                   :graph "g" :block-kind "audit-receipt"
                                   :aead-key-b64 (key64 32) :blind-key-b64 (key64 64)})]
      (-> (audit/create-receipt signer (:encrypt-fn profile) {"outcome" "allow"})
          (.then (fn [{:keys [cid bytes]}]
                   (-> (audit/verify-receipt cid bytes (:decrypt-fn profile) (:did other))
                       (.then (fn [_] (is false "wrong signer must fail")))
                       (.catch (fn [e]
                                 (is (= :audit-signer-mismatch (:type (ex-data e)))))))))
          (.then (fn [_] (done)))
          (.catch (fn [e] (is false (.-message e)) (done)))))))
