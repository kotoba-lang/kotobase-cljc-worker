(ns kotobase.cljc-worker.ipns-test
  "run-ipns-head/run-ipns-publish against a real async fake R2 bucket (same
  fidelity contract as worker-test's make-fake-bucket: async .get/.put,
  minted etags, unconditional put on a nil onlyIf)."
  (:require [cljs.test :refer [deftest is testing async]]
            [kotobase.cljc-worker.worker :as w]
            [kotobase.ipns :as ipns]))

(defn- make-fake-bucket []
  (let [store (atom {})
        etag-seq (atom 0)]
    #js {:get (fn [k]
                (js/Promise.resolve
                 (when-let [{:keys [value etag]} (get @store k)]
                   #js {:text (fn [] (js/Promise.resolve value))
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

(def seed (js/Uint8Array.from (clj->js (range 32))))

(defn- signed-record [{:keys [name sequence]}]
  (ipns/sign-head seed {:name name :value "bafyrei-example"
                        :sequence sequence :valid_until "2027-01-01T00:00:00Z"}))

(defn- response->clj [^js resp]
  (-> (.json resp) (.then #(js->clj % :keywordize-keys true))))

(deftest publish-then-head-round-trips
  (async done
    (let [bucket (make-fake-bucket)
          record (signed-record {:name "k51test1" :sequence 1})]
      (-> (w/run-ipns-publish bucket "" record)
          (.then (fn [^js resp]
                   (is (= 200 (.-status resp)))
                   (w/run-ipns-head bucket "" "k51test1")))
          (.then (fn [^js resp]
                   (is (= 200 (.-status resp)))
                   (response->clj resp)))
          (.then (fn [body]
                   (is (= "k51test1" (:name body)))
                   (is (= 1 (:sequence body)))
                   (is (:signature_multibase body))
                   (done)))
          (.catch (fn [e] (is false (str "unexpected rejection: " (.-message e))) (done)))))))

(deftest head-of-unknown-name-is-404
  (async done
    (-> (w/run-ipns-head (make-fake-bucket) "" "k51never-published")
        (.then (fn [^js resp] (is (= 404 (.-status resp))) (done))))))

(deftest publish-rejects-an-unsigned-record
  (async done
    (-> (w/run-ipns-publish (make-fake-bucket) ""
                            {:name "k51evil" :value "x" :sequence 1
                             :valid_until "2027-01-01T00:00:00Z"})
        (.then (fn [^js resp] (is (= 401 (.-status resp))) (done))))))

(deftest publish-rejects-a-tampered-signature
  (async done
    (let [record (assoc (signed-record {:name "k51tamper" :sequence 1}) :value "evil-value")]
      (-> (w/run-ipns-publish (make-fake-bucket) "" record)
          (.then (fn [^js resp] (is (= 401 (.-status resp))) (done)))))))

(deftest publish-rejects-sequence-rollback
  (async done
    (let [bucket (make-fake-bucket)]
      (-> (w/run-ipns-publish bucket "" (signed-record {:name "k51seq" :sequence 5}))
          (.then (fn [_] (w/run-ipns-publish bucket "" (signed-record {:name "k51seq" :sequence 5}))))
          (.then (fn [^js resp]
                   (testing "same sequence again is a rollback, not an update"
                     (is (= 409 (.-status resp))))
                   (done)))))))

(deftest publish-accepts-a-higher-sequence
  (async done
    (let [bucket (make-fake-bucket)]
      (-> (w/run-ipns-publish bucket "" (signed-record {:name "k51advance" :sequence 1}))
          (.then (fn [_] (w/run-ipns-publish bucket "" (signed-record {:name "k51advance" :sequence 2}))))
          (.then (fn [^js resp] (is (= 200 (.-status resp))) (done)))))))
