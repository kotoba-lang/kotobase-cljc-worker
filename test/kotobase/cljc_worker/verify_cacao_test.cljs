(ns kotobase.cljc-worker.verify-cacao-test
  "verify-cacao regression coverage -- particularly the :exp NaN-bypass this
  fixes: js/Date.parse returns NaN (not nil, not a throw) on an unparseable
  string, and NaN < anything is false in JS, so a naive `(< (js/Date.parse
  exp) now)` treated a malformed :exp as permanently valid rather than
  rejecting it."
  (:require [cljs.test :refer [deftest is testing]]
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
