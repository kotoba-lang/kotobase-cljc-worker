(ns kotobase.cljc-worker.handler-test
  (:require #?(:clj  [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer [deftest is testing] :include-macros true])
            [kotobase.cljc-worker.handler :as h]
            [kotobase-peer.core :as eng]))

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
  ;; ADR-2607032430 D1: transact never hydrates/rebuilds -- it only appends a
  ;; novelty tx block -- yet every read (datoms/pull/q) must still see that
  ;; data immediately (via hot-datoms), before anything is ever folded.
  (let [store (mem-store)
        tx "[{:db/id \"keybackup/zA\" :aozora.keyBackup/did \"did:key:zA\" :aozora.keyBackup/blob \"blobA\"}
             {:db/id \"keybackup/zB\" :aozora.keyBackup/did \"did:key:zB\" :aozora.keyBackup/blob \"blobB\"}
             {:db/id \"acct/a\" :atproto.account/handle \"a.aozora.app\"}]"
        w (h/handle store "transact" {:graph g :tx_edn tx} "did:web:x")]
    (testing "transact commits + advances head, without folding"
      (is (:ok w))
      (is (string? (:commit w)))
      (is (= 5 (:datom_count w)) "datom_count is THIS tx's own quad count")
      (is (= 1 (:novelty_size w)) "one novelty block, nothing folded yet")
      (is (some? ((:head-get store) g)))
      (is (nil? (eng/latest-snapshot-cid (:get-fn store) (:commit w)))
          "still all-novelty -- do-transact never folds inline"))
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
    (testing "q sees novelty-only data via a rebuilt hot db"
      (let [r (h/handle store "q" {:graph g :query_edn "[nil \":atproto.account/handle\" nil]"} nil)]
        (is (:ok r))
        (is (= [{:s "acct/a" :p ":atproto.account/handle" :o "a.aozora.app"}] (:rows r)))))
    (testing "a second transact chains onto the head, still novelty-only"
      (let [w2 (h/handle store "transact"
                         {:graph g :tx_edn "[{:db/id \"keybackup/zC\" :aozora.keyBackup/did \"did:key:zC\"}]"} "did:web:x")]
        (is (:ok w2))
        (is (= 1 (:datom_count w2)) "datom_count is the second tx's own count, not the graph total")
        (is (= 2 (:novelty_size w2)))
        (is (= 3 (count (:datoms (h/handle store "datoms"
                                           {:graph g :index ":avet"
                                            :components_edn [":aozora.keyBackup/did"]} nil)))))
        (testing "fold compacts novelty into an indexed snapshot without losing data"
          (let [before (h/do-datoms store {:graph g})
                f (h/handle store "fold" {:graph g} "did:web:x")]
            (is (:ok f))
            (is (true? (:folded f)))
            (is (= 2 (:novelty_folded f)))
            (is (some? (eng/latest-snapshot-cid (:get-fn store) (:commit f))))
            (is (= (set (:datoms before)) (set (:datoms (h/do-datoms store {:graph g})))))
            (testing "reads after fold still honor filters, now served cold"
              (is (= 3 (count (:datoms (h/handle store "datoms"
                                                 {:graph g :index ":avet"
                                                  :components_edn [":aozora.keyBackup/did"]} nil))))))
            (testing "folding again with nothing new to fold is a no-op that doesn't touch the head"
              (let [head-before ((:head-get store) g)
                    f2 (h/handle store "fold" {:graph g} "did:web:x")]
                (is (:ok f2))
                (is (false? (:folded f2)))
                (is (nil? (:commit f2)))
                (is (= head-before ((:head-get store) g)))))
            (testing "a third transact after a fold still reads correctly (mixed snapshot+novelty)"
              (let [w3 (h/handle store "transact"
                                 {:graph g :tx_edn "[{:db/id \"keybackup/zD\" :aozora.keyBackup/did \"did:key:zD\"}]"}
                                 "did:web:x")]
                (is (:ok w3))
                (is (= 1 (:novelty_size w3)))
                (is (= 4 (count (:datoms (h/handle store "datoms"
                                                   {:graph g :index ":avet"
                                                    :components_edn [":aozora.keyBackup/did"]} nil)))))))))))))

(deftest fold-on-empty-or-already-folded-graph-is-a-safe-no-op
  (let [store (mem-store)]
    (testing "folding a graph that has never been written to"
      (let [f (h/handle store "fold" {:graph g} nil)]
        (is (:ok f))
        (is (false? (:folded f)))
        (is (nil? ((:head-get store) g)) "no head write attempted")))))

(deftest unknown-method
  (is (= "MethodNotImplemented" (:error (h/handle (mem-store) "frobnicate" {} nil)))))
