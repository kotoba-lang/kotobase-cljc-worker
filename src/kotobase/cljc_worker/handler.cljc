(ns kotobase.cljc-worker.handler
  "Pure XRPC dispatch for the CLJC kotobase datom-plane worker — the filter-
  honoring replacement for the WASM worker that ignored index/components_edn/limit
  and rehydrated the whole graph per read (ADR-2607022330 addendum 2).

  Everything here is a pure function of an injected `store` and the parsed request,
  so it is node-testable with an in-memory store. The workerd shell
  (kotobase.cljc-worker.worker) supplies the R2-backed store + CACAO verification.

  store keys:
    :get-fn      (fn [cid])          -> block bytes | nil
    :put!        (fn [cid bytes])    -> _ (writes block)
    :head-get    (fn [graph])        -> chain-cid string | nil
    :head-put!   (fn [graph chain])  -> _ (updates the graph's chain head)"
  (:require #?(:clj  [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            [clojure.string :as str]
            [kotobase-engine.core :as eng]))

(def datomic-ns "ai.gftd.apps.kotobase.datomic")

;; ── tx_edn (vector of entity maps) → engine quads ────────────────────────────

(defn tx-edn->quads
  "Parse a kotobase `tx_edn` string — a vector of entity maps
  `[{:db/id \"e\" :ns/attr v …} …]` — into `{:s :p :o}` quads (one per non-:db/id
  pair). Reads the whole string as EDN (no brace-splitting), so map/vector values
  containing literal braces are safe (the old tx-edn.mjs brace-split bug)."
  [tx-edn]
  (let [forms (edn/read-string tx-edn)]
    (for [ent forms
          :let [s (:db/id ent)]
          [k v] ent
          :when (not= k :db/id)]
      ;; (str :ns/attr) already includes the leading ':' — the PDS's datom
      ;; consumers key on ":ns/attr" (with the colon), so keep it verbatim.
      {:s (str s) :p (str k) :o (str v)})))

;; ── read/write against the graph's persisted chain ──────────────────────────

(defn- snapshot-of [store graph]
  (when-let [chain (:head-get store)]
    (some->> (chain graph) (eng/latest-snapshot-cid (:get-fn store)))))

(defn- index-kw [index]
  (when (seq index) (keyword (cond-> index (str/starts-with? index ":") (subs 1)))))

(defn do-datoms
  "`datomic.datoms` — filtered read via cold-datoms (never rehydrates the db).
  body: {:graph :index :components_edn :limit}."
  [store {:keys [graph index components_edn limit]}]
  (let [snap (snapshot-of store graph)]
    (if (nil? snap)
      {:ok true :graph graph :datoms []}
      {:ok true :graph graph
       :datoms (eng/cold-datoms (:get-fn store) snap
                                {:index (or (index-kw index) :eavt)
                                 :components (vec components_edn)
                                 :limit limit})})))

(defn do-transact
  "`datomic.transact` — hydrate the graph's db (~1×), assert the tx quads, commit,
  advance the head. `auth-did` is the CACAO-verified issuer (the shell verifies it
  == graph owner); nil here means the shell already gated it."
  [store {:keys [graph tx_edn]} _auth-did]
  (let [get-fn (:get-fn store)
        prev-chain ((:head-get store) graph)
        prev-snap  (some->> prev-chain (eng/latest-snapshot-cid get-fn))
        db  (-> (eng/hydrate-db get-fn prev-snap)
                (eng/transact (tx-edn->quads tx_edn)))
        chain (eng/commit! (:put! store) get-fn db prev-chain)]
    ((:head-put! store) graph chain)
    {:ok true :graph graph :commit chain
     :datom_count (count (eng/datoms db))}))

(defn do-q
  "`datomic.q` — triple-pattern query. Hydrates the graph's db (writes are rarer
  than the hammered keyed reads this worker fixes) then routes through kqe. body:
  {:graph :query_edn} where query_edn is a `[s p o]` pattern (nil = wildcard)."
  [store {:keys [graph query_edn]}]
  (let [snap (snapshot-of store graph)
        db   (eng/hydrate-db (:get-fn store) snap)
        pat  (edn/read-string query_edn)]
    {:ok true :graph graph :rows (vec (eng/q db pat))}))

(defn do-pull
  "`datomic.pull` — all attrs of one entity. body: {:graph :entity}."
  [store {:keys [graph entity]}]
  (let [snap (snapshot-of store graph)]
    {:ok true :graph graph
     :entity entity
     :attrs (if (nil? snap)
              {}
              ;; entity's datoms via the eavt prefix, folded into {attr [vals]}
              (reduce (fn [m {:keys [a v_edn]}] (update m a (fnil conj []) v_edn))
                      {}
                      (eng/cold-datoms (:get-fn store) snap
                                       {:index :eavt :components [entity]})))}))

;; ── dispatch ─────────────────────────────────────────────────────────────────

(defn handle
  "Dispatch a parsed XRPC call. `method` is the NSID suffix after
  `ai.gftd.apps.kotobase.datomic.`; `body` is the keywordized JSON body;
  `auth-did` is the CACAO-verified issuer or nil. Returns a plain response map;
  never throws for a known method (errors become `{:ok false :error …}`)."
  [store method body auth-did]
  (try
    (case method
      "datoms"   (do-datoms store body)
      "transact" (do-transact store body auth-did)
      "q"        (do-q store body)
      "pull"     (do-pull store body)
      {:ok false :error "MethodNotImplemented" :method method})
    (catch #?(:clj Exception :cljs :default) e
      {:ok false :error "InternalError"
       :message #?(:clj (.getMessage e) :cljs (.-message e))})))
