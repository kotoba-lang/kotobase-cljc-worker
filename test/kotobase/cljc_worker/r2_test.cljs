(ns kotobase.cljc-worker.r2-test
  (:require [cljs.test :refer [deftest is testing async]]
            [kotobase.cljc-worker.crypto :as crypto]
            [kotobase.cljc-worker.r2 :as r2]
            [kotobase-peer.core :as eng]))

(deftest with-blocks-bridges-async-r2-to-async-cold-datoms
  ;; Persist a snapshot into an in-memory block map, then serve those blocks
  ;; ASYNC (promise per fetch) through the trampoline and run cold-datoms
  ;; (itself a Promise on cljs since the ADR-2607051000 crypto seam — the
  ;; trampoline retries block-miss REJECTIONS, not just sync throws) against
  ;; it — it must equal a direct read. Crypto fns are the worker's explicit
  ;; plaintext-passthrough profile.
  (async done
    (let [blocks (atom {})
          put! (fn [cid b] (swap! blocks assoc cid b))
          sync-get (fn [cid] (get @blocks cid))
          db (eng/transact (eng/empty-db)
                           [["keybackup/zA" ":aozora.keyBackup/did" "did:key:zA"]
                            ["keybackup/zA" ":aozora.keyBackup/blob" "blobA"]
                            ["keybackup/zB" ":aozora.keyBackup/did" "did:key:zB"]])
          ;; async R2 fetch: resolve the block on a microtask
          fetch1 (fn [cid] (js/Promise.resolve (get @blocks cid)))
          everything (constantly true)]
      (-> (eng/snapshot! put! sync-get db nil crypto/blind-fn crypto/encrypt-fn)
          (.then (fn [chain]
                   (let [snap (eng/latest-snapshot-cid sync-get chain)]
                     (-> (eng/cold-datoms sync-get snap
                                          {:index :eavt :components ["keybackup/zA"]}
                                          everything crypto/blind-fn crypto/decrypt-fn)
                         (.then (fn [direct]
                                  (-> (r2/with-blocks fetch1
                                        (fn [g] (eng/cold-datoms g snap
                                                                 {:index :eavt :components ["keybackup/zA"]}
                                                                 everything crypto/blind-fn crypto/decrypt-fn)))
                                      (.then (fn [via-r2]
                                               (is (= (set direct) (set via-r2)) "async-R2 read == direct read")
                                               (is (= 2 (count via-r2)))
                                               ;; a point lookup via the trampoline too
                                               (r2/with-blocks fetch1
                                                 (fn [g] (eng/cold-datoms g snap
                                                                          {:index :avet
                                                                           :components [":aozora.keyBackup/did" "did:key:zB"]}
                                                                          everything crypto/blind-fn crypto/decrypt-fn))))))))))))
          (.then (fn [rows]
                   (is (= [{:e "keybackup/zB" :a ":aozora.keyBackup/did"
                            :v_edn "\"did:key:zB\"" :added true}] (vec rows)))
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
;; (like a real object store). CRITICAL fidelity point (a live-tested lesson,
;; not a guess): a put with NO onlyIf condition is UNCONDITIONAL — it must
;; always succeed, even overwriting an existing object — R2 has no implicit
;; "if absent" behavior. An earlier version of this mock got this wrong
;; (treated a missing onlyIf the same as onlyIf.etagMatches ""), which let a
;; test pass against a fake that DIDN'T match real R2 semantics while the
;; equivalent live code path failed every single first-write-to-a-new-graph.

(defn- make-fake-bucket []
  (let [store (atom {})            ; key -> {:value :etag}
        etag-seq (atom 0)]
    #js {:get (fn [k]
                (js/Promise.resolve
                 (when-let [{:keys [value etag]} (get @store k)]
                   #js {:text (fn [] (js/Promise.resolve value)) :etag etag})))
         :put (fn [k v ^js opts]
                (js/Promise.resolve
                 (let [required (some-> opts .-onlyIf .-etagMatches)]
                   (if (and (some? required)
                            (not= required (:etag (get @store k))))
                     nil        ; onlyIf.etagMatches present AND mismatched -> reject
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

(deftest r2-put-head-if-match-nil-etag-is-unconditional
  ;; The documented, accepted narrow race: a nil etag (no prior read, or the
  ;; key was absent) writes unconditionally — this is the ONLY path where two
  ;; writers can race undetected, and only for the very first commit of a
  ;; graph, never for accumulated history (every subsequent write goes
  ;; through the real-etag CAS path below).
  (async done
    (let [bucket (make-fake-bucket)]
      (-> (r2/r2-put-head-if-match bucket "heads/g1" "chainA" nil)
          (.then (fn [ok?] (is ok? "first write succeeds")))
          (.then (fn [_] (r2/r2-put-head-if-match bucket "heads/g1" "chainB" nil)))
          (.then (fn [ok?]
                   (is ok? "a nil-etag put is unconditional — it overwrites, it does not reject")
                   (r2/r2-get-head bucket "heads/g1")))
          (.then (fn [{:keys [chain]}]
                   (is (= "chainB" chain) "the second (unconditional) writer wins, as expected")
                   (done)))))))

(deftest r2-put-head-if-match-rejects-on-stale-etag
  ;; The case that actually matters at real write volume: EVERY write after
  ;; the first carries a real etag from its own head read, and a stale one
  ;; (someone else committed in between) must be rejected, not silently
  ;; accepted.
  (async done
    (let [bucket (make-fake-bucket)]
      (-> (r2/r2-put-head-if-match bucket "heads/g1" "chainA" nil)
          (.then (fn [_] (r2/r2-get-head bucket "heads/g1")))
          (.then (fn [{:keys [etag]}]
                   ;; a THIRD writer commits in between, advancing the head
                   (-> (r2/r2-put-head-if-match bucket "heads/g1" "chainB" etag)
                       (.then (fn [ok?] (is ok? "the in-between writer succeeds")))
                       ;; now a STALE writer retries its put with the OLD etag
                       (.then (fn [_] (r2/r2-put-head-if-match bucket "heads/g1" "chainC-stale" etag))))))
          (.then (fn [ok?]
                   (is (false? ok?) "a write against a now-stale etag is rejected")
                   (r2/r2-get-head bucket "heads/g1")))
          (.then (fn [{:keys [chain]}]
                   (is (= "chainB" chain) "the rejected stale writer never clobbered the winner")
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

;; ── immutable block memory cache (ADR-2607167000) ─────────────────────────────

(deftest cached-block-bytes-fetches-r2-once-per-cid
  (async done
    (let [calls (atom 0)
          bytes (js/Uint8Array. #js [1 2 3])
          bucket #js {:get (fn [_k]
                             (swap! calls inc)
                             (js/Promise.resolve
                              #js {:arrayBuffer (fn [] (js/Promise.resolve (.-buffer bytes)))}))}]
      (-> (r2/cached-block-bytes bucket "t/" "bafy-cache-test-1")
          (.then (fn [b1]
                   (is (= 3 (.-length b1)))
                   (r2/cached-block-bytes bucket "t/" "bafy-cache-test-1")))
          (.then (fn [b2]
                   (is (= 3 (.-length b2)))
                   (is (= 1 @calls) "second read served from isolate memory, no R2 get")
                   (done)))
          (.catch (fn [e] (is false (str "rejected: " e)) (done)))))))

(deftest cached-block-bytes-does-not-cache-nil
  (async done
    (let [calls (atom 0)
          bucket #js {:get (fn [_k] (swap! calls inc) (js/Promise.resolve nil))}]
      (-> (r2/cached-block-bytes bucket "t/" "bafy-cache-test-absent")
          (.then (fn [b1]
                   (is (nil? b1))
                   (r2/cached-block-bytes bucket "t/" "bafy-cache-test-absent")))
          (.then (fn [b2]
                   (is (nil? b2))
                   (is (= 2 @calls) "absent blocks are re-checked (not negatively cached)")
                   (done)))
          (.catch (fn [e] (is false (str "rejected: " e)) (done)))))))
