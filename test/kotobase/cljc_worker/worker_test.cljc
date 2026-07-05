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
  (:require [cljs.test :refer [deftest is testing async]]
            [kotobase.cljc-worker.worker :as w]))

;; Same fidelity contract as r2-test's make-fake-bucket (this repo's own
;; precedent for mocking R2 without a live Cloudflare binding): async
;; .get/.put, minted etags, unconditional put on a nil onlyIf.
(defn- make-fake-bucket []
  (let [store (atom {})
        etag-seq (atom 0)]
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
                       #js {:etag new-etag})))))}))

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
