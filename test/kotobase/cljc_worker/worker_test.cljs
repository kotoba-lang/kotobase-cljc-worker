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
            [kotobase.cljc-worker.worker :as w]))

;; Same fidelity contract as r2-test's make-fake-bucket (this repo's own
;; precedent for mocking R2 without a live Cloudflare binding): async
;; .get/.put, minted etags, including create-if-absent conditional puts.
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
                  (let [required (some-> opts .-onlyIf .-etagMatches)
                        excluded (some-> opts .-onlyIf .-etagDoesNotMatch)
                        current (:etag (get @store k))]
                    (if (or (and (some? required) (not= required current))
                            (and (= "*" excluded) (some? current))
                            (and (some? excluded) (not= "*" excluded)
                                 (= excluded current)))
                      nil
                      (let [new-etag (str "etag-" (swap! etag-seq inc))]
                        (swap! store assoc k {:value v :etag new-etag})
                        #js {:etag new-etag})))))})))

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

(defn- rotation-body [graph rid to-key ledger-hash]
  {:graph graph
   :expected_ledger_seq -1
   :expected_ledger_hash nil
   :rotation_id rid
   :rotation_subject "did:key:owner"
   :rotation_purpose ":authority"
   :rotation_from_epoch 0
   :tx_edn (pr-str [{:db/id (str "kagi:rotation:" rid)
                      :rotation/id rid
                      :rotation/subject "did:key:owner"
                      :rotation/purpose :authority
                      :rotation/from-key "old"
                      :rotation/to-key to-key
                      :rotation/from-epoch 0}
                     {:db/id "kagi:ledger:0"
                      :ledger/seq 0 :ledger/prev-hash nil
                      :ledger/hash ledger-hash}])})

(deftest concurrent-competing-rotations-publish-exactly-one-head
  (async done
    (let [bucket (make-fake-bucket)
          graph "rotation-race"]
      ;; Establish a real-etag graph head without a ledger, then launch both
      ;; rotations before either Promise has completed its conditional PUT.
      (-> (w/run-write bucket "" "transact"
                       {:graph graph :tx_edn "[{:db/id \"seed\" :app/kind :seed}]"} nil)
          (.then (fn [_]
                   (js/Promise.all
                    #js [(w/run-write bucket "" "transactRotation"
                                      (rotation-body graph "r-a" "new-a" "h-a") nil)
                         (w/run-write bucket "" "transactRotation"
                                      (rotation-body graph "r-b" "new-b" "h-b") nil)])))
          (.then (fn [results]
                   (let [rs (js->clj results :keywordize-keys true)
                         accepted (filter :ok rs)
                         rejected (remove :ok rs)]
                     (is (= 1 (count accepted))
                         "R2 head CAS allows exactly one competing child")
                     (is (= 1 (count rejected)))
                     (is (contains? #{"RotationPreconditionFailed"
                                      "CompetingRotationChild"}
                                    (:error (first rejected)))
                         "the CAS loser revalidates against the winner's fresh snapshot")
                     (done))))
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
