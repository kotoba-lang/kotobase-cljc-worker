(ns kotobase.cljc-worker.r2-test
  (:require [cljs.test :refer [deftest is testing async]]
            [kotobase.cljc-worker.r2 :as r2]
            [kotobase-engine.core :as eng]))

(deftest with-blocks-bridges-async-r2-to-sync-cold-datoms
  ;; Persist a snapshot into an in-memory block map, then serve those blocks
  ;; ASYNC (promise per fetch) through the trampoline and run the SYNC
  ;; cold-datoms against it — it must equal a direct sync read.
  (async done
    (let [blocks (atom {})
          put! (fn [cid b] (swap! blocks assoc cid b))
          sync-get (fn [cid] (get @blocks cid))
          db (eng/transact (eng/empty-db)
                           [["keybackup/zA" ":aozora.keyBackup/did" "did:key:zA"]
                            ["keybackup/zA" ":aozora.keyBackup/blob" "blobA"]
                            ["keybackup/zB" ":aozora.keyBackup/did" "did:key:zB"]])
          chain (eng/commit! put! sync-get db nil)
          snap  (eng/latest-snapshot-cid sync-get chain)
          ;; async R2 fetch: resolve the block on a microtask
          fetch1 (fn [cid] (js/Promise.resolve (get @blocks cid)))
          direct (eng/cold-datoms sync-get snap
                                  {:index :eavt :components ["keybackup/zA"]})]
      (-> (r2/with-blocks fetch1
            (fn [g] (eng/cold-datoms g snap {:index :eavt :components ["keybackup/zA"]})))
          (.then (fn [via-r2]
                   (is (= (set direct) (set via-r2)) "async-R2 read == sync read")
                   (is (= 2 (count via-r2)))
                   ;; a point lookup via the trampoline too
                   (r2/with-blocks fetch1
                     (fn [g] (eng/cold-datoms g snap
                                              {:index :avet
                                               :components [":aozora.keyBackup/did" "did:key:zB"]})))))
          (.then (fn [rows]
                   (is (= [{:e "keybackup/zB" :a ":aozora.keyBackup/did"
                            :v_edn "\"did:key:zB\"" :added true}] rows))
                   (done)))
          (.catch (fn [e] (is false (str "trampoline threw: " e)) (done)))))))

(deftest with-blocks-propagates-non-miss-errors
  (async done
    (-> (r2/with-blocks (fn [_] (js/Promise.resolve nil))
          (fn [_] (throw (js/Error. "boom"))))
        (.then (fn [_] (is false "should have rejected") (done)))
        (.catch (fn [e] (is (= "boom" (.-message e))) (done))))))

;; ── head CAS: a fake R2 bucket enforcing onlyIf.etagMatches ─────────────────
;; Mirrors just enough of the real R2Bucket surface (.get/.put, R2Object with
;; .text()/.etag) to prove r2-get-head/r2-put-head-if-match's contract without
;; a live Cloudflare binding — a new etag is minted on every successful put
;; (like a real object store), so a stale reader's put is REJECTED, never
;; silently accepted.

(defn- make-fake-bucket []
  (let [store (atom {})            ; key -> {:value :etag}
        etag-seq (atom 0)]
    #js {:get (fn [k]
                (js/Promise.resolve
                 (when-let [{:keys [value etag]} (get @store k)]
                   #js {:text (fn [] (js/Promise.resolve value)) :etag etag})))
         :put (fn [k v ^js opts]
                (js/Promise.resolve
                 (let [required (some-> opts .-onlyIf .-etagMatches)
                       current  (:etag (get @store k))]
                   (if (not= (or required "") (or current ""))
                     nil        ; real R2: onlyIf failed -> resolves null, no write
                     (let [new-etag (str "etag-" (swap! etag-seq inc))]
                       (swap! store assoc k {:value v :etag new-etag})
                       #js {:etag new-etag})))))
         :__store store}))

(deftest r2-get-head-nil-for-absent-key
  (async done
    (-> (r2/r2-get-head (make-fake-bucket) "heads/g1")
        (.then (fn [r] (is (= {:chain nil :etag nil} r)) (done))))))

(deftest r2-get-head-returns-chain-and-etag-once-written
  (async done
    (let [bucket (make-fake-bucket)]
      (-> (r2/r2-put-head-if-match bucket "heads/g1" "chainA" nil)
          (.then (fn [ok?] (is ok?) (r2/r2-get-head bucket "heads/g1")))
          (.then (fn [{:keys [chain etag]}]
                   (is (= "chainA" chain))
                   (is (some? etag))
                   (done)))))))

(deftest r2-put-head-if-match-rejects-on-stale-etag
  (async done
    (let [bucket (make-fake-bucket)]
      (-> (r2/r2-put-head-if-match bucket "heads/g1" "chainA" nil)
          (.then (fn [ok?] (is ok? "first create-if-absent write succeeds")))
          ;; a second writer racing off the SAME (now-stale) nil etag must lose
          (.then (fn [_] (r2/r2-put-head-if-match bucket "heads/g1" "chainB-stale" nil)))
          (.then (fn [ok?]
                   (is (false? ok?) "a second create-if-absent after the key exists is rejected")
                   (r2/r2-get-head bucket "heads/g1")))
          (.then (fn [{:keys [chain]}]
                   (is (= "chainA" chain) "the rejected writer never clobbered the winner")
                   (done)))))))

(deftest r2-put-head-if-match-two-racers-exactly-one-wins
  ;; The actual failure mode this fix closes: two overlapping transacts both
  ;; read the SAME (chain, etag) pair, then both attempt to advance the head.
  ;; Exactly one must win; the loser must be told (not silently swallowed) so
  ;; the caller retries instead of losing its commit's visibility.
  (async done
    (let [bucket (make-fake-bucket)]
      (-> (r2/r2-put-head-if-match bucket "heads/g1" "chain0" nil)
          (.then (fn [_] (r2/r2-get-head bucket "heads/g1")))
          (.then (fn [{:keys [etag]}]
                   ;; both racers read the SAME etag here
                   (js/Promise.all
                    #js [(r2/r2-put-head-if-match bucket "heads/g1" "chainA" etag)
                         (r2/r2-put-head-if-match bucket "heads/g1" "chainB" etag)])))
          (.then (fn [^js results]
                   (let [[a b] (vec results)
                         wins (filter true? [a b])]
                     (is (= 1 (count wins)) "exactly one racer's CAS succeeds")
                     (r2/r2-get-head bucket "heads/g1"))))
          (.then (fn [{:keys [chain]}]
                   (is (contains? #{"chainA" "chainB"} chain)
                       "the surviving head is one of the two racers' commits, not corrupted")
                   (done)))))))
