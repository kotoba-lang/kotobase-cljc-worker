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
   (deftest handle-returns-a-clean-error-not-a-broken-promise-on-malformed-tx-edn
     ;; do-transact's tx-edn->quads calls edn/read-string on the caller-
     ;; supplied tx_edn -- a malformed string throws SYNCHRONOUSLY, before
     ;; do-transact ever returns a value/Promise, which used to skip
     ;; `handle`'s `.catch (js/Promise.resolve resp) ...` wrapping and hit
     ;; its outer `(catch ... (err e))` bare -- returning a PLAIN map
     ;; instead of the Promise every cljs caller's `.then` assumes `handle`
     ;; always returns (a raw `TypeError: ...handle(...).then is not a
     ;; function`, not a clean rejection, on the live production write
     ;; path). If `handle` regresses to that bare form, `.then` below
     ;; throws synchronously and this test fails loudly, not silently.
     (async done
       (-> (h/handle (mem-store) "transact" {:graph g :tx_edn "not valid edn ["} "did:web:x")
           (.then (fn [r]
                    (is (not (:ok r)))
                    (is (= "InternalError" (:error r)))
                    (done)))
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
   (deftest bounded-fold-drains-a-backlog-across-repeated-calls
     ;; gftdcojp/app-aozora#78 / kotobase-peer#16: a cron/ops caller can pass
     ;; :max_novelty to make guaranteed forward progress against a backlog
     ;; too large to fold in one unbounded pass -- each call folds only the
     ;; OLDEST max_novelty tx blocks, leaving the rest as novelty, and repeated
     ;; calls converge to the same fully-folded state an unbounded fold would
     ;; reach in one call.
     (async done
       (let [store (mem-store)
             tx (fn [n] (str "[{:db/id \"e" n "\" :ns/attr \"v" n "\"}]"))]
         (-> (h/handle store "transact" {:graph g :tx_edn (tx 1)} "did:web:x")
             (.then (fn [_] (h/handle store "transact" {:graph g :tx_edn (tx 2)} "did:web:x")))
             (.then (fn [_] (h/handle store "transact" {:graph g :tx_edn (tx 3)} "did:web:x")))
             (.then (fn [_] (h/do-datoms store {:graph g})))
             (.then (fn [before]
                      (-> (h/handle store "fold" {:graph g :max_novelty 2} "did:web:x")
                          (.then (fn [f1]
                                   (testing "first bounded call folds only the oldest 2, leaves 1"
                                     (is (:ok f1))
                                     (is (true? (:folded f1)))
                                     (is (= 2 (:novelty_folded f1)))
                                     (is (= 1 (:novelty_remaining f1)))
                                     (is (= 1 (eng/novelty-size (:get-fn store) (:commit f1)))))
                                   (h/handle store "fold" {:graph g :max_novelty 2} "did:web:x")))
                          (.then (fn [f2]
                                   (testing "second bounded call folds the remaining 1 (fewer than the cap)"
                                     (is (:ok f2))
                                     (is (true? (:folded f2)))
                                     (is (= 1 (:novelty_folded f2)))
                                     (is (= 0 (:novelty_remaining f2)))
                                     (is (zero? (eng/novelty-size (:get-fn store) (:commit f2)))))
                                   (h/do-datoms store {:graph g})))
                          (.then (fn [after]
                                   (is (= (set (:datoms before)) (set (:datoms after)))
                                       "bounded folds across multiple calls lose nothing")
                                   (done))))))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest do-fold-cache-get-cache-put-are-threaded-through-and-populate-the-cache
     ;; ADR-2607120730 Part 1: do-fold passes (:cache-get store)/(:cache-put!
     ;; store) through to eng/fold!'s memoized-hydration arity. This proves
     ;; the WIRING (store -> do-fold -> eng/fold!) is correct -- the
     ;; underlying cache-hit-skips-decrypt behavior itself is kotobase-peer's
     ;; own test suite's job (fold-bang-cache-get-cache-put-avoids-
     ;; rehydrating-...), not re-proven here.
     ;;
     ;; `store`'s :head-put! is a no-op (base's is real) so two `do-fold`
     ;; calls against `store` both retry the SAME starting chain -- exactly
     ;; the production scenario (a cron tick that keeps failing later never
     ;; actually advances the head, so every retry re-reads the identical
     ;; still-unfolded snapshot).
     (async done
       (let [cache (atom {})
             base (mem-store)
             store (assoc base
                          :cache-get (fn [k] (js/Promise.resolve (get @cache k)))
                          :cache-put! (fn [k v] (js/Promise.resolve (swap! cache assoc k v)))
                          :head-put! (fn [_ _] nil))
             tx (fn [n] (str "[{:db/id \"e" n "\" :ns/attr \"v" n "\"}]"))]
         (-> (h/handle base "transact" {:graph g :tx_edn (tx 1)} "did:web:x")
             (.then (fn [_] (h/handle base "fold" {:graph g} "did:web:x")))
             (.then (fn [_] (h/handle base "transact" {:graph g :tx_edn (tx 2)} "did:web:x")))
             (.then (fn [_]
                      (-> (h/do-fold store {:graph g})
                          (.then (fn [f1]
                                   (is (:ok f1)) (is (true? (:folded f1)))
                                   (is (pos? (count @cache)) "cache-put! populated the cache")
                                   (-> (h/do-fold store {:graph g})
                                       (.then (fn [f2]
                                                (is (:ok f2)) (is (true? (:folded f2)))
                                                (is (= (:commit f1) (:commit f2))
                                                    "retrying the identical fold via the cache converges to the identical result")
                                                (done)))))))))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest do-fold-async-get-fn-is-threaded-through-and-produces-a-correct-fold
     ;; ADR-2607120730 follow-up: do-fold passes (:async-get-fn store) through
     ;; to eng/fold!'s async-scan arity, routing the hydrate step itself
     ;; through prolly-tree.core/scan-prefix-async instead of the with-blocks-
     ;; trampolined sync path -- this proves the WIRING is correct end to end
     ;; (correctness); the underlying O(N) vs O(N^2) performance story is
     ;; kotobase-peer's own test suite's job, and was additionally confirmed
     ;; live against the real stuck yoro-social-v2 backlog (5130 entries,
     ;; 806ms via scan-prefix-async vs. a 300s CPU budget exceeded before).
     (async done
       (let [base (mem-store)
             store (assoc base :async-get-fn (fn [cid] (js/Promise.resolve ((:get-fn base) cid))))
             tx (fn [n] (str "[{:db/id \"e" n "\" :ns/attr \"v" n "\"}]"))]
         (-> (h/handle base "transact" {:graph g :tx_edn (tx 1)} "did:web:x")
             (.then (fn [_] (h/handle base "transact" {:graph g :tx_edn (tx 2)} "did:web:x")))
             (.then (fn [_] (h/do-datoms base {:graph g})))
             (.then (fn [before]
                      (-> (h/handle store "fold" {:graph g} "did:web:x")
                          (.then (fn [f]
                                   (is (:ok f)) (is (true? (:folded f)))
                                   (is (= 0 (eng/novelty-size (:get-fn base) (:commit f)))
                                       "fold via :async-get-fn still fully compacts")
                                   (h/do-datoms base {:graph g})))
                          (.then (fn [after]
                                   (is (= (set (:datoms before)) (set (:datoms after)))
                                       "folding via :async-get-fn loses/duplicates nothing")
                                   (done))))))
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

#?(:cljs
   (deftest diag-hydrate-cost-counts-entries-in-the-indexed-snapshot
     ;; ADR-2607120730 follow-up: diagHydrateCost is a read-only diagnostic
     ;; that walks the current indexed snapshot via
     ;; prolly-tree.core/scan-prefix-async (:async-get-fn, a direct fetch
     ;; bypassing with-blocks entirely) and reports how many leaf entries it
     ;; holds -- proving the wiring (store -> do-diag-hydrate-cost ->
     ;; scan-prefix-async) is correct end to end.
     (async done
       (let [base (mem-store)
             store (assoc base :async-get-fn (fn [cid] (js/Promise.resolve ((:get-fn base) cid))))
             tx (fn [n] (str "[{:db/id \"e" n "\" :ns/attr \"v" n "\"}]"))]
         (-> (h/handle store "transact" {:graph g :tx_edn (tx 1)} "did:web:x")
             (.then (fn [_] (h/handle store "transact" {:graph g :tx_edn (tx 2)} "did:web:x")))
             (.then (fn [_] (h/handle store "transact" {:graph g :tx_edn (tx 3)} "did:web:x")))
             (.then (fn [_] (h/handle store "fold" {:graph g} "did:web:x")))
             (.then (fn [f]
                      (is (:ok f)) (is (true? (:folded f)) "fold populates the indexed snapshot")
                      (h/handle store "diagHydrateCost" {:graph g} nil)))
             (.then (fn [d]
                      (is (:ok d))
                      (is (some? (:snapshot d)))
                      (is (= 3 (:entry_count d)) "3 folded entities -> 3 leaf entries in the :eavt tree")
                      (is (number? (:elapsed_ms d)))
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest diag-hydrate-cost-on-an-unfolded-graph-is-a-safe-zero
     (async done
       (let [store (assoc (mem-store) :async-get-fn (fn [_] (js/Promise.resolve nil)))]
         (-> (h/handle store "diagHydrateCost" {:graph g} nil)
             (.then (fn [d]
                      (is (:ok d))
                      (is (nil? (:snapshot d)))
                      (is (= 0 (:entry_count d)))
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest diag-commit-cost-measures-hydrate-and-commit-separately-without-touching-the-head
     ;; ADR-2607120730 follow-up: diagCommitCost isolates qs/commit!'s cost
     ;; (the 4x prolly-tree.core/build-tree index rebuild) from
     ;; hydrate-db-cached's cost -- proving the wiring is correct (store ->
     ;; do-diag-commit-cost -> eng/hydrate-db-cached + qs/commit!) and that
     ;; it never reads or advances the real head.
     (async done
       (let [base (mem-store)
             store (assoc base
                          :async-get-fn (fn [cid] (js/Promise.resolve ((:get-fn base) cid)))
                          :put! (fn [_cid _bytes] nil)) ; buffered/discarded, matches production's real put! during commit!
             tx (fn [n] (str "[{:db/id \"e" n "\" :ns/attr \"v" n "\"}]"))]
         (-> (h/handle base "transact" {:graph g :tx_edn (tx 1)} "did:web:x")
             (.then (fn [_] (h/handle base "fold" {:graph g} "did:web:x"))) ; real fold on `base`, warm-up
             (.then (fn [_]
                      (let [head-before ((:head-get base) g)]
                        (-> (h/handle store "diagCommitCost" {:graph g} nil)
                            (.then (fn [d]
                                     (is (:ok d) (str "resp: " (pr-str d)))
                                     (is (some? (:snapshot d)))
                                     (is (number? (:hydrate_ms d)))
                                     (is (number? (:commit_ms d)))
                                     (is (= head-before ((:head-get base) g))
                                         "diagCommitCost never advances/rewrites the real head")
                                     (done)))))))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

;; ── materialized views (ADR-2607166600 IVM) ──────────────────────────────────

#?(:cljs
   (deftest fold-with-views-edn-materializes-and-do-view-serves-fresh-rows
     (async done
       (let [store (mem-store)]
         (-> (h/handle store "transact"
                       {:graph g :tx_edn "[{:db/id \"p1\" :yoro.post/uri \"at://p1\" :yoro.post/text \"hi\"}]"}
                       "did:web:x")
             (.then (fn [_] (h/handle store "fold"
                                      {:graph g :views_edn "{\"feed\" {\"attrs\" [\":yoro.post/uri\"]}}"}
                                      "did:web:x")))
             (.then (fn [f]
                      (is (:ok f))
                      (is (true? (:folded f)))
                      (h/handle store "view" {:graph g :view "feed"} nil)))
             (.then (fn [v]
                      (is (:ok v))
                      (is (= {"attrs" [":yoro.post/uri"]} (:spec v)))
                      (is (= [{:e "p1" :a ":yoro.post/uri" :v_edn "\"at://p1\"" :added true}]
                             (:datoms v))
                          "only spec attrs — the text row is excluded")
                      ;; post-fold novelty is merged fresh by do-view
                      (h/handle store "transact"
                                {:graph g :tx_edn "[{:db/id \"p2\" :yoro.post/uri \"at://p2\"}]"}
                                "did:web:x")))
             (.then (fn [_] (h/handle store "view" {:graph g :view "feed"} nil)))
             (.then (fn [v2]
                      (is (= #{"at://p1" "at://p2"}
                             (set (map #(-> % :v_edn (subs 1) (->> (drop-last 1) (apply str)))
                                       (:datoms v2))))
                          "an unfolded novelty assertion appears without a new fold")
                      ;; spec-less fold carries the view forward
                      (h/handle store "fold" {:graph g} "did:web:x")))
             (.then (fn [_] (h/handle store "view" {:graph g :view "feed"} nil)))
             (.then (fn [v3]
                      (is (:ok v3))
                      (is (= 2 (count (:datoms v3))) "carry-forward re-materialized both rows")
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest do-view-unknown-view-is-a-clean-error
     (async done
       (let [store (mem-store)]
         (-> (h/handle store "transact" {:graph g :tx_edn "[{:db/id \"e\" :a/x \"v\"}]"} "did:web:x")
             (.then (fn [_] (h/handle store "view" {:graph g :view "nope"} nil)))
             (.then (fn [v]
                      (is (false? (:ok v)))
                      (is (= "ViewNotFound" (:error v)))
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest views-only-fold-on-zero-novelty-graph-materializes-immediately
     ;; a quiet graph (all novelty already folded) + views_edn must still
     ;; materialize — the zero-novelty early return is bypassed when views
     ;; are declared (ADR-2607166600 follow-up, closed).
     (async done
       (let [store (mem-store)]
         (-> (h/handle store "transact" {:graph g :tx_edn "[{:db/id \"p\" :a/x \"v\"}]"} "did:web:x")
             (.then (fn [_] (h/handle store "fold" {:graph g} "did:web:x")))   ; drain novelty
             (.then (fn [_] (h/handle store "fold"
                                      {:graph g :views_edn "{\"xs\" {\"attrs\" [\":a/x\"]}}"}
                                      "did:web:x")))
             (.then (fn [f]
                      (is (:ok f))
                      (is (true? (:folded f)) "views-only fold ran despite zero novelty")
                      (h/handle store "view" {:graph g :view "xs"} nil)))
             (.then (fn [v]
                      (is (:ok v))
                      (is (= [{:e "p" :a ":a/x" :v_edn "\"v\"" :added true}] (:datoms v)))
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

;; ── visibility redaction (ADR-2607174500 = ADR-2607050500 Phase 3) ───────────

#?(:cljs
   (deftest policy-redacts-protected-attrs-for-anonymous-and-capability-opens
     (async done
       (let [store (mem-store)
             caps {:did "did:web:reader" :resources ["kotoba://can/datom:read-protected"]}]
         (-> (h/handle store "transact"
                       {:graph g
                        :tx_edn (str "[{:db/id \"kotobase.policy/read\" "
                                     ":kotobase.policy/protected-prefixes \"[\\\":dm.\\\"]\"} "
                                     "{:db/id \"m1\" :dm.message/text \"secret hello\"} "
                                     "{:db/id \"p1\" :yoro.post/text \"public post\"}]")}
                       "did:web:x")
             ;; anonymous: protected prefix redacted, public + policy visible
             (.then (fn [_] (h/handle store "datoms" {:graph g} nil)))
             (.then (fn [r]
                      (let [attrs (set (map :a (:datoms r)))]
                        (is (contains? attrs ":yoro.post/text"))
                        (is (contains? attrs ":kotobase.policy/protected-prefixes")
                            "policy itself stays inspectable")
                        (is (not (contains? attrs ":dm.message/text"))
                            "protected attr redacted for anonymous"))
                      ;; q is redacted the same way
                      (h/handle store "q" {:graph g :query_edn "[nil \":dm.message/text\" nil]"} nil)))
             (.then (fn [r]
                      (is (empty? (:rows r)) "q sees no protected rows anonymously")
                      ;; pull of the protected entity comes back empty
                      (h/handle store "pull" {:graph g :entity "m1"} nil)))
             (.then (fn [r]
                      (is (empty? (:attrs r)) "pull redacts the protected entity")
                      ;; capability opens everything
                      (h/handle store "datoms" {:graph g} caps)))
             (.then (fn [r]
                      (is (contains? (set (map :a (:datoms r))) ":dm.message/text")
                          "datom:read-protected capability opens protected rows")
                      ;; view rows honor the same filter
                      (h/handle store "fold"
                                {:graph g :views_edn "{\"dms\" {\"attrs\" [\":dm.message/text\" \":yoro.post/text\"]}}"}
                                "did:web:x")))
             (.then (fn [_] (h/handle store "view" {:graph g :view "dms"} nil)))
             (.then (fn [r]
                      (let [attrs (set (map :a (:datoms r)))]
                        (is (contains? attrs ":yoro.post/text"))
                        (is (not (contains? attrs ":dm.message/text"))
                            "view reads redact for anonymous too"))
                      (h/handle store "view" {:graph g :view "dms"} caps)))
             (.then (fn [r]
                      (is (contains? (set (map :a (:datoms r))) ":dm.message/text")
                          "capability opens view rows")
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest policy-less-graph-stays-fully-public
     (async done
       (let [store (mem-store)]
         (-> (h/handle store "transact"
                       {:graph g :tx_edn "[{:db/id \"m1\" :dm.message/text \"hi\"}]"}
                       "did:web:x")
             (.then (fn [_] (h/handle store "datoms" {:graph g} nil)))
             (.then (fn [r]
                      (is (contains? (set (map :a (:datoms r))) ":dm.message/text")
                          "no policy entity → everything visible (zero regression)")
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))

#?(:cljs
   (deftest owner-based-disclosure-viewer-sees-own-protected-rows
     (async done
       (let [store (mem-store)
             alice {:did "did:web:alice" :resources []}]
         (-> (h/handle store "transact"
                       {:graph g
                        :tx_edn (str "[{:db/id \"kotobase.policy/read\" "
                                     ":kotobase.policy/protected-prefixes \"[\\\":dm.\\\"]\" "
                                     ":kotobase.policy/owner-attrs \"[\\\":dm.message/author\\\"]\"} "
                                     "{:db/id \"m1\" :dm.message/author \"did:web:alice\" :dm.message/text \"alice note\"} "
                                     "{:db/id \"m2\" :dm.message/author \"did:web:bob\" :dm.message/text \"bob note\"}]")}
                       "did:web:x")
             (.then (fn [_] (h/handle store "datoms" {:graph g} alice)))
             (.then (fn [r]
                      (let [texts (set (keep (fn [d] (when (= ":dm.message/text" (:a d)) (:v_edn d))) (:datoms r)))]
                        (is (contains? texts "\"alice note\"") "owner sees own")
                        (is (not (contains? texts "\"bob note\"")) "owner not another's"))
                      (h/handle store "datoms" {:graph g} nil)))
             (.then (fn [r]
                      (is (empty? (filter #(= ":dm.message/text" (:a %)) (:datoms r))) "anon sees none")
                      (done)))
             (.catch (fn [e] (is false (str "rejected: " e)) (done))))))))
