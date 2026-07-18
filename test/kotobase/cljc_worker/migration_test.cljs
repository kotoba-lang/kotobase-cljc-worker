(ns kotobase.cljc-worker.migration-test
  (:require [cljs.test :refer [deftest is async]]
            [kotobase.cacao :as cacao]
            [kotobase.server.security.crypto :as crypto]
            [kotobase.server.security.migration :as migration]
            [kotobase-peer.core :as eng]))

(defn- key64 [offset]
  (cacao/bytes->base64
   (js/Uint8Array.from (clj->js (map #(+ offset %) (range 32))))))

(deftest plaintext-graph-reencrypts-with-logical-parity
  (async done
    (let [source (atom {})
          put! (fn [cid bytes] (swap! source assoc cid bytes))
          get! #(get @source %)
          db (eng/transact (eng/empty-db)
                           [{:s "e1" :p ":app/name" :o "Alice"}
                            {:s "e2" :p ":app/name" :o "Bob"}])
          target (crypto/profile {:security-mode :private :tenant-id "t" :graph "g"
                                  :aead-key-b64 (key64 0) :blind-key-b64 (key64 32)})]
      (-> (eng/snapshot! put! get! db nil (:blind-fn crypto/plaintext-profile)
                         (:encrypt-fn crypto/plaintext-profile))
          (.then (fn [source-head]
                   (migration/reencrypt-graph get! source-head crypto/plaintext-profile target)))
          (.then (fn [{:keys [source-head target-head datom-count blocks]}]
                   (is (= 2 datom-count))
                   (is (not= source-head target-head))
                   (is (seq blocks))
                   (done)))
          (.catch (fn [e] (is false (.-message e)) (done)))))))
