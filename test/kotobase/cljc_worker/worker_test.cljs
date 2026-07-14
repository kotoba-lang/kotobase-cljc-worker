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
;; .get/.put, minted etags, unconditional put on a nil onlyIf.
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
                  (let [required (some-> opts .-onlyIf .-etagMatches)]
                    (if (and (some? required)
                             (not= required (:etag (get @store k))))
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
