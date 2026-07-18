(ns kotobase.cljc-worker.authority-test
  (:require [cljs.test :refer [deftest is]]
            [kotobase.cacao :as cacao]
            [kotobase.cid :as cid]
            [kotobase.server.security.authority :as authority]
            ["@ipld/dag-cbor" :as dag-cbor]
            ["@noble/curves/ed25519.js" :refer [ed25519]]))

(def root-seed (js/Uint8Array.from (clj->js (range 32))))
(def middle-seed (js/Uint8Array.from (clj->js (range 32 64))))
(def leaf-seed (js/Uint8Array.from (clj->js (range 64 96))))
(defn- did [seed] (cid/did-key-from-ed25519-pub (.getPublicKey ed25519 seed)))

(defn- grant [seed audience resources iat exp]
  (let [p {:domain "kotobase.net" :iss (did seed) :aud audience :version "1"
           :nonce "grant-nonce" :iat iat :exp exp :statement nil :resources resources}
        sig (.sign ed25519 (cid/text->bytes (cacao/cacao-siwe-message p)) seed)]
    (cacao/bytes->base64
     (.encode dag-cbor #js {:h #js {:t "caip122"} :p (clj->js p)
                           :s #js {:t "EdDSA" :s (cacao/bytes->base64url sig)}}))))

(deftest delegation-chain-enforces-root-continuity-attenuation-and-revocation
  (let [now (.now js/Date)
        iat (.toISOString (js/Date. (- now 1000)))
        root-exp (.toISOString (js/Date. (+ now 300000)))
        leaf-exp (.toISOString (js/Date. (+ now 240000)))
        graph "g"
        broad [(str "kotoba://graph/" graph) "kotoba://can/datom:read"
               "kotoba://can/datom:read-protected"]
        narrow [(str "kotoba://graph/" graph) "kotoba://can/datom:read"]
        g1 (grant root-seed (did middle-seed) broad iat root-exp)
        g2 (grant middle-seed (did leaf-seed) narrow iat leaf-exp)
        opts {:principal (did leaf-seed) :graph graph :now-ms now
              :trusted-root-dids #{(did root-seed)}}
        verified (authority/verify-chain [g1 g2] opts)]
    (is (:delegated? verified))
    (is (= (set narrow) (:effective-caps verified)))
    (is (nil? (authority/verify-chain [g1 g2]
                                      (assoc opts :trusted-root-dids #{"did:key:evil"}))))
    (is (nil? (authority/verify-chain [g1 g2]
                                      (assoc opts :revoked-credential-cids
                                             #{(second (:credential-cids verified))}))))
    (let [escalated (grant middle-seed (did leaf-seed) broad iat leaf-exp)
          narrow-parent (grant root-seed (did middle-seed) narrow iat root-exp)]
      (is (nil? (authority/verify-chain [narrow-parent escalated] opts))))))
