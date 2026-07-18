(ns kotobase.cljc-worker.verify-cacao-test
  "verify-cacao regression coverage -- particularly the :exp NaN-bypass this
  fixes: js/Date.parse returns NaN (not nil, not a throw) on an unparseable
  string, and NaN < anything is false in JS, so a naive `(< (js/Date.parse
  exp) now)` treated a malformed :exp as permanently valid rather than
  rejecting it."
  (:require [cljs.test :refer [deftest is testing async]]
            [kotobase.cljc-worker.worker :as w]
            [kotobase.cacao :as cacao]
            [kotobase.cid :as cid]
            ["@ipld/dag-cbor" :as dag-cbor]
            ["@noble/curves/ed25519.js" :refer [ed25519]]))

(def seed (js/Uint8Array.from (clj->js (range 32))))

(defn- mint-with-exp
  "Like kotobase.cacao/mint-cacao, but with an explicit (possibly
  malformed, possibly nil) :exp -- mint-cacao itself always computes a
  well-formed ISO :exp from :ttl-sec, so this is the only way to sign a
  CACAO whose :exp isn't a parseable date, to exercise verify-cacao's
  expiry check directly rather than just its happy path."
  [exp-str]
  (let [pub (.getPublicKey ed25519 seed)
        did (cid/did-key-from-ed25519-pub pub)
        p {:domain "kotobase.net" :iss did :aud "did:web:kotobase.aozora.app" :version "1"
           :nonce "test-nonce-1" :iat "2027-01-01T00:00:00Z" :exp exp-str :statement nil
           :resources ["kotoba://can/datom:transact" "kotoba://graph/g"]}
        msg (cacao/cacao-siwe-message p)
        sig (.sign ed25519 (cid/text->bytes msg) seed)
        cacao-js #js {:h #js {:t "caip122"}
                      :p (clj->js p)
                      :s #js {:t "EdDSA" :s (cacao/bytes->base64url sig)}}]
    (cacao/bytes->base64 (.encode dag-cbor cacao-js))))

(deftest verify-cacao-accepts-a-valid-unexpired-cacao
  (let [{:keys [cacao-b64]} (cacao/mint-cacao {:secret-key seed :aud "did:web:kotobase.aozora.app"
                                                :capability "datom:transact" :graph "g"})]
    (is (string? (w/verify-cacao cacao-b64)))))

(deftest verified-claims-preserve-signed-capability-resources
  (let [{:keys [cacao-b64]}
        (cacao/mint-cacao {:secret-key seed :aud "did:web:kotobase.aozora.app"
                           :capability "datom:transact"
                           :extra-capabilities ["kagi:rotate" "kagi:ledger"]
                           :graph "g"})
        claims (w/verify-cacao-claims cacao-b64)]
    (is (string? (:issuer claims)))
    (is (contains? (set (:resources claims)) "kotoba://can/datom:transact"))
    (is (contains? (set (:resources claims)) "kotoba://can/kagi:rotate"))
    (is (contains? (set (:resources claims)) "kotoba://can/kagi:ledger"))))

(deftest audience-and-nonce-authorization-fail-closed
  (let [{:keys [cacao-b64]}
        (cacao/mint-cacao {:secret-key seed :aud "did:web:kotobase.aozora.app"
                           :capability "datom:transact" :graph "g"})
        claims (w/verify-cacao-claims cacao-b64)]
    (is (w/valid-cacao-audience?
         #js {:KOTOBASE_CACAO_AUDIENCE "did:web:kotobase.aozora.app"} claims))
    (is (false? (w/valid-cacao-audience?
                 #js {:KOTOBASE_CACAO_AUDIENCE "did:web:other.example"} claims)))
    (is (false? (w/valid-cacao-audience? #js {} claims))
        "an unconfigured production audience is not a wildcard")
    (is (w/valid-cacao-nonce? (:nonce claims)))
    (is (w/valid-cacao-window? claims))
    (is (false? (w/valid-cacao-window? (assoc claims :exp nil))))
    (let [one-hour-exp (.toISOString
                        (js/Date. (+ (.getTime (js/Date.)) 3600000)))]
      (is (false? (w/valid-cacao-window? (assoc claims :exp one-hour-exp)))
          "one-hour bearer write tokens exceed the ten-minute maximum"))
    (is (false? (w/valid-cacao-nonce? "short")))
    (is (false? (w/valid-cacao-nonce? "../../head")))))

(deftest cacao-nonce-is-consumed-exactly-once
  (async done
    (let [objects (atom #{})
          bucket #js {:put (fn [k _ ^js opts]
                             (js/Promise.resolve
                              (when (and (= "*" (some-> opts .-onlyIf .-etagDoesNotMatch))
                                         (not (contains? @objects k)))
                                (swap! objects conj k)
                                #js {:etag "created"})))}
          claims {:issuer "did:key:test" :nonce "0123456789abcdef"}]
      (-> (w/consume-cacao-nonce! bucket "p/" claims)
          (.then (fn [first?]
                   (is first?)
                   (w/consume-cacao-nonce! bucket "p/" claims)))
          (.then (fn [second?]
                   (is (false? second?))
                   (is (= 1 (count @objects)))
                   (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest nonce-cleanup-is-prefix-scoped-and-age-bounded
  (async done
    (let [now 200000000
          deleted (atom nil)
          old-date (js/Date. (- now 90000000))
          new-date (js/Date. (- now 1000))
          bucket #js {:list (fn [opts]
                              (is (= "p/cacao-nonce/v1/" (.-prefix opts)))
                              (js/Promise.resolve
                               #js {:objects #js [#js {:key "p/cacao-nonce/v1/a/old"
                                                       :uploaded old-date}
                                                  #js {:key "p/cacao-nonce/v1/a/new"
                                                       :uploaded new-date}]
                                    :truncated false}))
                      :delete (fn [keys]
                                (reset! deleted (js->clj keys))
                                (js/Promise.resolve nil))}]
      (-> (w/cleanup-expired-cacao-nonces! bucket "p/" now)
          (.then (fn [count]
                   (is (= 1 count))
                   (is (= ["p/cacao-nonce/v1/a/old"] @deleted))
                   (done)))
          (.catch (fn [e] (is false (str e)) (done)))))))

(deftest verify-cacao-rejects-a-well-formed-expired-cacao
  (let [{:keys [cacao-b64]} (cacao/mint-cacao {:secret-key seed :aud "did:web:kotobase.aozora.app"
                                                :capability "datom:transact" :graph "g"
                                                :now-ms (- (.getTime (js/Date.)) (* 1000 3600))
                                                :ttl-sec 60})]
    (is (nil? (w/verify-cacao cacao-b64)))))

(deftest verify-cacao-rejects-a-malformed-exp-instead-of-treating-it-as-never-expired
  (testing "the exploit shape: a garbage :exp string must not silently make
            expired? permanently false"
    (is (nil? (w/verify-cacao (mint-with-exp "not-a-real-date"))))))

(deftest verify-cacao-accepts-a-cacao-with-no-exp-field
  (testing "absent :exp means no expiry check at all -- this fn's existing,
            documented 'expiry-if-present' scope, unaffected by the fix"
    (is (string? (w/verify-cacao (mint-with-exp nil))))))
