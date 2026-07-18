(ns kotobase.cljc-worker.keywrap-test
  (:require [cljs.test :refer [deftest is async]]
            [kotobase.server.security.keywrap :as keywrap]))

(deftest hpke-keyring-wrap-roundtrip-and-context-binding
  (async done
    (let [keyring {"active" "k1" "keys" {"k1" {"aead" "secret-a"
                                                  "blind" "secret-b"}}}]
      (-> (keywrap/generate-recipient-keypair)
          (.then (fn [{:keys [public-key-b64 private-key-b64]}]
                   (-> (keywrap/wrap-keyring public-key-b64 keyring "tenant-a")
                       (.then (fn [envelope]
                                (js/Promise.all
                                 #js [(-> (keywrap/unwrap-keyring private-key-b64 envelope "tenant-a")
                                          (.then #(= keyring %)))
                                      (-> (keywrap/unwrap-keyring private-key-b64 envelope "tenant-b")
                                          (.then (fn [_] false)) (.catch (fn [_] true)))]))))))
          (.then (fn [results]
                   (is (true? (aget results 0)))
                   (is (true? (aget results 1)) "HPKE info/AAD binds tenant context")
                   (done)))
          (.catch (fn [e] (is false (.-message e)) (done)))))))
