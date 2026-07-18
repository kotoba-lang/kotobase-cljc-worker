(ns kotobase.cljc-worker.crypto-test
  (:require [cljs.test :refer [deftest is async]]
            [kotobase.cacao :as cacao]
            [kotobase.server.security.crypto :as crypto]))

(defn- key64 [offset]
  (cacao/bytes->base64
   (js/Uint8Array.from (clj->js (map #(+ offset %) (range 32))))))

(defn- bytes= [a b]
  (= (vec a) (vec b)))

(deftest production-profile-roundtrip-is-deterministic-and-blinded
  (async done
    (let [profile (crypto/profile {:security-mode :private :graph "bafy-graph-a"
                                   :aead-key-b64 (key64 0) :blind-key-b64 (key64 32)})
          plain (js/Uint8Array.from #js [1 2 3 4])]
      (-> (js/Promise.all
           #js [((:encrypt-fn profile) plain)
                ((:encrypt-fn profile) plain)
                ((:blind-fn profile) ":secret/value")])
          (.then (fn [values]
                   (let [a (aget values 0) b (aget values 1) token (aget values 2)]
                     (is (= :aes-256-gcm-siv (:kind profile)))
                     (is (bytes= a b) "same content converges across retries")
                     (is (not= token ":secret/value"))
                     (-> ((:decrypt-fn profile) a)
                         (.then (fn [decoded] (is (bytes= plain decoded))))))))
          (.then (fn [_] (done)))
          (.catch (fn [e] (is false (.-message e)) (done)))))))

(deftest ciphertext-is-bound-to-graph-and-detects-tampering
  (async done
    (let [opts {:security-mode :private :aead-key-b64 (key64 0)
                :blind-key-b64 (key64 32)}
          a (crypto/profile (assoc opts :graph "graph-a"))
          b (crypto/profile (assoc opts :graph "graph-b"))
          plain (js/Uint8Array.from #js [9 8 7])]
      (-> ((:encrypt-fn a) plain)
          (.then (fn [ciphertext]
                   (let [tampered (.slice ciphertext)]
                     (aset tampered (dec (.-length tampered))
                           (bit-xor 1 (aget tampered (dec (.-length tampered)))))
                     (js/Promise.all
                      #js [(-> ((:decrypt-fn b) ciphertext)
                               (.then (fn [_] false)) (.catch (fn [_] true)))
                           (-> ((:decrypt-fn a) tampered)
                               (.then (fn [_] false)) (.catch (fn [_] true)))]))))
          (.then (fn [rejected]
                   (is (true? (aget rejected 0)) "different graph AAD rejects")
                   (is (true? (aget rejected 1)) "modified tag/ciphertext rejects")
                   (done)))
          (.catch (fn [e] (is false (.-message e)) (done)))))))

(deftest private-mode-never-falls-back-to-plaintext
  (is (thrown? js/Error (crypto/profile {:security-mode :private :graph "g"})))
  (is (= :plaintext (:kind (crypto/profile {:security-mode :legacy-public :graph "g"})))))

(deftest keyring-rotation-keeps-old-ciphertext-readable
  (async done
    (let [old-entry {"aead" (key64 0) "blind" (key64 32)}
          new-entry {"aead" (key64 64) "blind" (key64 96)}
          base {:security-mode :private :tenant-id "tenant-a" :graph "graph-a"}
          old-profile (crypto/profile
                       (assoc base :keyring {"active" "k-old"
                                             "keys" {"k-old" old-entry}}))
          rotated (crypto/profile
                   (assoc base :keyring {"active" "k-new"
                                         "keys" {"k-new" new-entry
                                                 "k-old" old-entry}}))
          wrong-tenant (crypto/profile
                        (assoc base :tenant-id "tenant-b"
                               :keyring {"active" "k-new"
                                         "keys" {"k-new" new-entry
                                                 "k-old" old-entry}}))
          plain (js/Uint8Array.from #js [4 5 6])]
      (-> ((:encrypt-fn old-profile) plain)
          (.then (fn [old-ciphertext]
                   (js/Promise.all
                    #js [(-> ((:decrypt-fn rotated) old-ciphertext)
                             (.then #(bytes= plain %)))
                         (-> ((:decrypt-fn wrong-tenant) old-ciphertext)
                             (.then (fn [_] false)) (.catch (fn [_] true)))])))
          (.then (fn [results]
                   (is (true? (aget results 0)) "retained key id decrypts pre-rotation data")
                   (is (true? (aget results 1)) "tenant is authenticated AAD")
                   (is (= "k-new" (:key-id rotated)))
                   (done)))
          (.catch (fn [e] (is false (.-message e)) (done)))))))
