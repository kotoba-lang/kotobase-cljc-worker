(ns kotobase.cljc-worker.handler-test
  "Handler contract tests. ADR-2607051000 adoption made every do-*/handle
  response a js/Promise on cljs (the engine's crypto seam is Promise-based
  there), so these tests are promise-chained under cljs.test/async — the
  node-test runner is the only consumer of this file in practice."
  (:require #?(:clj  [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer [deftest is testing async] :include-macros true])
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

(deftest tx-edn-parses-retraction-forms
  ;; ADR-2607071610 Phase 1: retract vectors dispatch BEFORE eavt (map-only)
  (is (= [{:s "post/1" :p ":yoro.post/text" :o "hello" :op :retract}]
         (h/tx-edn->quads "[[:db/retract \"post/1\" :yoro.post/text \"hello\"]]")))
  (is (= [{:s "post/1" :op :retract-entity}]
         (h/tx-edn->quads "[[:db/retractEntity \"post/1\"]]")))
  (is (= [{:s "e" :p ":a/x" :o "v"}
          {:s "post/1" :op :retract-entity}]
         (h/tx-edn->quads "[{:db/id \"e\" :a/x \"v\"} [:db/retractEntity \"post/1\"]]"))
      "entity maps and retraction forms mix in one tx"))

#?(:cljs
   (deftest datoms-on-empty-graph
     (async done
       (-> (h/do-datoms (mem-store) {:graph g :index ":eavt"})
           (.then (fn [r] (is (= {:ok true :graph g :datoms []} r)) (done)))
           (.catch (fn [e] (is false (str "rejected: " e)) (done)))))))

#?(:cljs
   (deftest unknown-method
     (async done
       (-> (h/handle (mem-store) "frobnicate" {} nil)
           (.then (fn [r] (is (= "MethodNotImplemented" (:error r))) (done)))
           (.catch (fn [e] (is false (str "rejected: " e)) (done)))))))

#?(:cljs
   (deftest fold-on-empty-or-already-folded-graph-is-a-safe-no-op
     (async done
       (let [store (mem-store)]
         (-> (h/handle store "fold" {:graph g} nil)
             (.then (fn [f]
                      (is (:ok f))
                      (is (false? (:folded f)))
                      (is (nil? ((:head-get store) g)) "no head write attempted")
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest transact-then-filtered-read-roundtrip
     ;; ADR-2607032430 D1: transact never hydrates/rebuilds -- it only appends a
     ;; novelty tx block -- yet every read (datoms/pull/q) must still see that
     ;; data immediately (via hot-datoms), before anything is ever folded.
     (async done
       (let [store (mem-store)
             tx "[{:db/id \"keybackup/zA\" :aozora.keyBackup/did \"did:key:zA\" :aozora.keyBackup/blob \"blobA\"}
                  {:db/id \"keybackup/zB\" :aozora.keyBackup/did \"did:key:zB\" :aozora.keyBackup/blob \"blobB\"}
                  {:db/id \"acct/a\" :atproto.account/handle \"a.aozora.app\"}]"]
         (-> (h/handle store "transact" {:graph g :tx_edn tx} "did:web:x")
             (.then (fn [w]
                      (testing "transact commits + advances head, without folding"
                        (is (:ok w))
                        (is (string? (:commit w)))
                        (is (= 5 (:datom_count w)) "datom_count is THIS tx's own quad count")
                        (is (= 1 (:novelty_size w)) "one novelty block, nothing folded yet")
                        (is (some? ((:head-get store) g)))
                        (is (nil? (eng/latest-snapshot-cid (:get-fn store) (:commit w)))
                            "still all-novelty -- do-transact never folds inline"))
                      (h/handle store "datoms"
                                {:graph g :index ":eavt" :components_edn ["keybackup/zA"]} nil)))
             (.then (fn [r]
                      (testing "datoms :eavt [entity] returns ONLY that entity (the getBackup query)"
                        (is (:ok r))
                        (is (= 2 (count (:datoms r))))
                        (is (every? #(= "keybackup/zA" (:e %)) (:datoms r))))
                      (h/handle store "datoms"
                                {:graph g :index ":avet"
                                 :components_edn [":aozora.keyBackup/did" "did:key:zB"]} nil)))
             (.then (fn [r]
                      (testing "datoms :avet [attr value] point lookup"
                        (is (= [{:e "keybackup/zB" :a ":aozora.keyBackup/did"
                                 :v_edn "\"did:key:zB\"" :added true}] (:datoms r))))
                      (h/handle store "datoms"
                                {:graph g :index ":avet"
                                 :components_edn [":aozora.keyBackup/did"] :limit 1} nil)))
             (.then (fn [r]
                      (testing "limit"
                        (is (= 1 (count (:datoms r)))))
                      (h/handle store "pull" {:graph g :entity "keybackup/zA"} nil)))
             (.then (fn [r]
                      (testing "pull folds an entity's attrs"
                        (is (:ok r))
                        (is (= #{":aozora.keyBackup/did" ":aozora.keyBackup/blob"}
                               (set (keys (:attrs r))))))
                      (h/handle store "q" {:graph g :query_edn "[nil \":atproto.account/handle\" nil]"} nil)))
             (.then (fn [r]
                      (testing "q sees novelty-only data via a rebuilt hot db"
                        (is (:ok r))
                        (is (= [{:s "acct/a" :p ":atproto.account/handle" :o "a.aozora.app"}] (:rows r))))
                      (h/handle store "transact"
                                {:graph g :tx_edn "[{:db/id \"keybackup/zC\" :aozora.keyBackup/did \"did:key:zC\"}]"}
                                "did:web:x")))
             (.then (fn [w2]
                      (testing "a second transact chains onto the head, still novelty-only"
                        (is (:ok w2))
                        (is (= 1 (:datom_count w2)) "datom_count is the second tx's own count, not the graph total")
                        (is (= 2 (:novelty_size w2))))
                      (h/handle store "datoms"
                                {:graph g :index ":avet" :components_edn [":aozora.keyBackup/did"]} nil)))
             (.then (fn [r]
                      (is (= 3 (count (:datoms r))))
                      (h/do-datoms store {:graph g})))
             (.then (fn [before]
                      (-> (h/handle store "fold" {:graph g} "did:web:x")
                          (.then (fn [f]
                                   (testing "fold compacts novelty into an indexed snapshot without losing data"
                                     (is (:ok f))
                                     (is (true? (:folded f)))
                                     (is (= 2 (:novelty_folded f)))
                                     (is (some? (eng/latest-snapshot-cid (:get-fn store) (:commit f)))))
                                   (h/do-datoms store {:graph g})))
                          (.then (fn [after]
                                   (is (= (set (:datoms before)) (set (:datoms after)))
                                       "fold loses nothing"))))))
             (.then (fn [_]
                      (h/handle store "datoms"
                                {:graph g :index ":avet" :components_edn [":aozora.keyBackup/did"]} nil)))
             (.then (fn [r]
                      (testing "reads after fold still honor filters, now served cold"
                        (is (= 3 (count (:datoms r)))))
                      (let [head-before ((:head-get store) g)]
                        (-> (h/handle store "fold" {:graph g} "did:web:x")
                            (.then (fn [f2]
                                     (testing "folding again with nothing new to fold is a no-op that doesn't touch the head"
                                       (is (:ok f2))
                                       (is (false? (:folded f2)))
                                       (is (nil? (:commit f2)))
                                       (is (= head-before ((:head-get store) g))))))))))
             (.then (fn [_]
                      (h/handle store "transact"
                                {:graph g :tx_edn "[{:db/id \"keybackup/zD\" :aozora.keyBackup/did \"did:key:zD\"}]"}
                                "did:web:x")))
             (.then (fn [w3]
                      (testing "a third transact after a fold still reads correctly (mixed snapshot+novelty)"
                        (is (:ok w3))
                        (is (= 1 (:novelty_size w3))))
                      (h/handle store "datoms"
                                {:graph g :index ":avet" :components_edn [":aozora.keyBackup/did"]} nil)))
             (.then (fn [r]
                      (is (= 4 (count (:datoms r))))
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest retraction-roundtrip-through-the-handler
     ;; ADR-2607071610 Phase 1 e2e at the worker layer: a [:db/retractEntity]
     ;; in tx_edn cancels the entity across novelty reads AND across a fold,
     ;; and the graph's materialized state actually shrinks.
     (async done
       (let [store (mem-store)]
         (-> (h/handle store "transact"
                       {:graph g :tx_edn "[{:db/id \"post/1\" :yoro.post/text \"hello\" :yoro.post/author \"did:key:zA\"}
                                           {:db/id \"post/2\" :yoro.post/text \"keep\"}]"}
                       "did:web:x")
             (.then (fn [w] (is (:ok w))
                      (h/handle store "transact"
                                {:graph g :tx_edn "[[:db/retractEntity \"post/1\"]]"} "did:web:x")))
             (.then (fn [w]
                      (is (:ok w) "retraction tx commits")
                      (is (= 1 (:datom_count w)))
                      (h/do-datoms store {:graph g})))
             (.then (fn [r]
                      (testing "novelty retraction cancels the entity in hot reads"
                        (is (= #{"post/2"} (set (map :e (:datoms r))))
                            "post/1's datoms are gone, post/2 survives"))
                      (h/handle store "pull" {:graph g :entity "post/1"} nil)))
             (.then (fn [r]
                      (is (= {} (:attrs r)) "pull of the retracted entity is empty")
                      (h/handle store "fold" {:graph g} "did:web:x")))
             (.then (fn [f]
                      (is (true? (:folded f)) "fold applies the retraction")
                      (h/do-datoms store {:graph g})))
             (.then (fn [r]
                      (testing "the folded snapshot no longer carries the retracted entity"
                        (is (= #{"post/2"} (set (map :e (:datoms r))))))
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))
