(ns kotobase.cljc-worker.keyring-admin-test
  (:require [cljs.test :refer [deftest is async]]
            [kotobase.server.security.keyring-admin :as admin]
            [kotobase.server.security.keywrap :as keywrap]))

(deftest create-rotate-retire-wrapped-keyring
  (async done
    (-> (keywrap/generate-recipient-keypair)
        (.then (fn [{:keys [public-key-b64 private-key-b64]}]
                 (-> (admin/create-wrapped-keyring public-key-b64 "tenant" "k1")
                     (.then (fn [e1]
                              (admin/rotate-wrapped-keyring private-key-b64 public-key-b64
                                                            e1 "tenant" "k2")))
                     (.then (fn [e2]
                              (-> (keywrap/unwrap-keyring private-key-b64 e2 "tenant")
                                  (.then (fn [ring]
                                           (is (= "k2" (get ring "active")))
                                           (is (= #{"k1" "k2"} (set (keys (get ring "keys")))))
                                           (admin/retire-wrapped-key private-key-b64 public-key-b64
                                                                     e2 "tenant" "k1"))))))
                     (.then (fn [e3]
                              (keywrap/unwrap-keyring private-key-b64 e3 "tenant"))))))
        (.then (fn [ring]
                 (is (= #{"k2"} (set (keys (get ring "keys")))))
                 (done)))
        (.catch (fn [e] (is false (.-message e)) (done))))))
