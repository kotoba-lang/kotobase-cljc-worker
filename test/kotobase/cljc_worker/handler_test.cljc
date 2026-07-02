(ns kotobase.cljc-worker.handler-test
  (:require #?(:clj  [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer [deftest is testing] :include-macros true])
            [kotobase.cljc-worker.handler :as h]
            [kotobase-engine.core :as eng]))

(defn- mem-store []
  (let [blocks (atom {}) heads (atom {})]
    {:get-fn    (fn [cid] (get @blocks cid))
     :put!      (fn [cid bytes] (swap! blocks assoc cid bytes))
     :head-get  (fn [graph] (get @heads graph))
     :head-put! (fn [graph chain] (swap! heads assoc graph chain))
     :blocks blocks :heads heads}))

(def g "kotobase/db/did:web:x/yoro-social")

(deftest tx-edn-parses-entity-maps-to-quads
  (is (= [{:s "keybackup/zA" :p ":aozora.keyBackup/did" :o "did:key:zA"}
          {:s "keybackup/zA" :p ":aozora.keyBackup/blob" :o "{\"v\":1}"}]
         (h/tx-edn->quads
          "[{:db/id \"keybackup/zA\" :aozora.keyBackup/did \"did:key:zA\" :aozora.keyBackup/blob \"{\\\"v\\\":1}\"}]"))))

(deftest datoms-on-empty-graph
  (is (= {:ok true :graph g :datoms []}
         (h/do-datoms (mem-store) {:graph g :index ":eavt"}))))

(deftest transact-then-filtered-read-roundtrip
  (let [store (mem-store)
        tx "[{:db/id \"keybackup/zA\" :aozora.keyBackup/did \"did:key:zA\" :aozora.keyBackup/blob \"blobA\"}
             {:db/id \"keybackup/zB\" :aozora.keyBackup/did \"did:key:zB\" :aozora.keyBackup/blob \"blobB\"}
             {:db/id \"acct/a\" :atproto.account/handle \"a.aozora.app\"}]"
        w (h/handle store "transact" {:graph g :tx_edn tx} "did:web:x")]
    (testing "transact commits + advances head"
      (is (:ok w))
      (is (string? (:commit w)))
      (is (= 5 (:datom_count w)))
      (is (some? ((:head-get store) g))))
    (testing "datoms :eavt [entity] returns ONLY that entity (the getBackup query)"
      (let [r (h/handle store "datoms"
                        {:graph g :index ":eavt" :components_edn ["keybackup/zA"]} nil)]
        (is (:ok r))
        (is (= 2 (count (:datoms r))))
        (is (every? #(= "keybackup/zA" (:e %)) (:datoms r)))))
    (testing "datoms :avet [attr value] point lookup"
      (let [r (h/handle store "datoms"
                        {:graph g :index ":avet"
                         :components_edn [":aozora.keyBackup/did" "did:key:zB"]} nil)]
        (is (= [{:e "keybackup/zB" :a ":aozora.keyBackup/did"
                 :v_edn "\"did:key:zB\"" :added true}] (:datoms r)))))
    (testing "limit"
      (is (= 1 (count (:datoms (h/handle store "datoms"
                                         {:graph g :index ":avet"
                                          :components_edn [":aozora.keyBackup/did"] :limit 1} nil))))))
    (testing "pull folds an entity's attrs"
      (let [r (h/handle store "pull" {:graph g :entity "keybackup/zA"} nil)]
        (is (:ok r))
        (is (= #{":aozora.keyBackup/did" ":aozora.keyBackup/blob"} (set (keys (:attrs r)))))))
    (testing "a second transact chains onto the head"
      (let [w2 (h/handle store "transact"
                         {:graph g :tx_edn "[{:db/id \"keybackup/zC\" :aozora.keyBackup/did \"did:key:zC\"}]"} "did:web:x")]
        (is (:ok w2))
        (is (= 6 (:datom_count w2)))
        (is (= 3 (count (:datoms (h/handle store "datoms"
                                           {:graph g :index ":avet"
                                            :components_edn [":aozora.keyBackup/did"]} nil)))))))))

(deftest unknown-method
  (is (= "MethodNotImplemented" (:error (h/handle (mem-store) "frobnicate" {} nil)))))
