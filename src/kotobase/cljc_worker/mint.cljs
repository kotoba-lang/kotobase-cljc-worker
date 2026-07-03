(ns kotobase.cljc-worker.mint
  "Dev/migration tool: mint a datom:transact CACAO for a deterministic seed and
  db-name, print {did, graph, cacao_b64} as JSON. Used to smoke-test the worker's
  transact path and to drive the yoro-social re-transact during cutover.

  Usage:  node out/mint.js <seed-hex-64> <db-name> <aud-did>"
  (:require [kotobase.cacao :as cacao]
            [kotobase.cid :as cid]
            ["@noble/curves/ed25519.js" :refer [ed25519]]))

(defn- hex->bytes [s]
  (let [n (/ (count s) 2) out (js/Uint8Array. n)]
    (dotimes [i n] (aset out i (js/parseInt (subs s (* 2 i) (+ 2 (* 2 i))) 16)))
    out))

(defn -main [& args]
  (if (= "graph" (first args))
    ;; `node out/mint.js graph <did> <db-name>` → print the canonical graph CID
    (let [[_ did db] args]
      (println (cid/canonical-graph did (or db "yoro-social"))))
    (apply -mint args)))

(defn -mint [& [seed-hex db-name aud]]
  (let [seed (hex->bytes (or seed-hex (apply str (repeat 64 "0"))))
        db   (or db-name "yoro-social")
        aud  (or aud "did:web:kotobase.aozora.app")
        did  (cid/did-key-from-ed25519-pub (.getPublicKey ed25519 seed))
        graph (cid/canonical-graph did db)
        {:keys [cacao-b64]} (cacao/mint-cacao {:secret-key seed :aud aud
                                               :capability "datom:transact"
                                               :extra-capabilities ["tx:create"]
                                               :graph graph :ttl-sec 600})]
    (println (js/JSON.stringify #js {:did did :db db :graph graph :cacao_b64 cacao-b64}))))
