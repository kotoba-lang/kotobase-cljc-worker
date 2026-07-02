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
