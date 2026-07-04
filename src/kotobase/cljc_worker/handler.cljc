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
            [kotobase-peer.core :as eng]))

(def datomic-ns "ai.gftd.apps.kotobase.datomic")

;; ── tx_edn (vector of entity maps) → engine quads ────────────────────────────

(defn tx-edn->quads
  "Parse a kotobase `tx_edn` string — a vector of entity maps
  `[{:db/id \"e\" :ns/attr v …} …]` — into `{:s :p :o}` quads. Datafication goes
  through the engine's canonical datom model (`eng/entities->datoms` =
  `datom.core/eavt`), the SAME `[e a v]` representation kgraph (the language's
  in-mem view) speaks — ONE shared datom model across transport, DB, and language
  (ADR-2607032500). Reads the whole string as EDN (no brace-splitting) so map/
  vector values with literal braces are safe (the old tx-edn.mjs brace-split bug).
  `(str :ns/attr)` keeps the leading ':' — PDS datom consumers key on \":ns/attr\"."
  [tx-edn]
  (map (fn [[e a v]] {:s (str e) :p (str a) :o (str v)})
       (eng/entities->datoms (edn/read-string tx-edn))))

;; ── read/write against the graph's persisted chain (ADR-2607032430 D1) ──────
;; The chain's head IS the unit of state now (snapshot + pending novelty), not
;; just its folded snapshot — every read goes through `eng/hot-datoms` so it
;; never misses data written since the last fold. `do-transact` never hydrates
;; the graph: it appends one novelty tx block (O(|tx|), independent of graph
;; size — the fix for the 2026-07-03 CPU-limit collapse). Folding is a
;; separate, explicit operation (`do-fold`) a cron/ops caller invokes — never
;; inline in a write's own request, so no single write's latency/CPU budget
;; can include an O(graph) compaction.

(defn- index-kw [index]
  (when (seq index) (keyword (cond-> index (str/starts-with? index ":") (subs 1)))))

(defn do-datoms
  "`datomic.datoms` — filtered read via hot-datoms (snapshot + novelty merge,
  range-pruned on the snapshot side; never a whole-graph rehydrate). body:
  {:graph :index :components_edn :limit}."
  [store {:keys [graph index components_edn limit]}]
  (let [chain ((:head-get store) graph)]
    {:ok true :graph graph
     :datoms (eng/hot-datoms (:get-fn store) chain
                             {:index (or (index-kw index) :eavt)
                              :components (vec components_edn)
                              :limit limit})}))

(defn do-transact
  "`datomic.transact` — append the tx quads as ONE novelty block and advance
  the chain. O(|tx_edn|) — independent of graph size; never hydrates or
  rebuilds an index (ADR-2607032430 D1, replacing the old hydrate+rebuild
  path that hit Cloudflare Workers' CPU limit under mass-write load).
  `auth-did` is the CACAO-verified issuer (the shell verifies it == graph
  owner); nil here means the shell already gated it. `novelty_size` in the
  response is an observability signal for when a `fold` (see `do-fold`) is
  worth invoking — this handler never folds itself."
  [store {:keys [graph tx_edn]} _auth-did]
  (let [get-fn (:get-fn store)
        prev-chain ((:head-get store) graph)
        quads (tx-edn->quads tx_edn)
        chain (eng/commit! (:put! store) get-fn quads prev-chain)]
    ((:head-put! store) graph chain)
    {:ok true :graph graph :commit chain
     :datom_count (count quads)
     :novelty_size (eng/novelty-size get-fn chain)}))

(defn- hot-db
  "The full hot db as of `chain` (snapshot + novelty merged) — for `do-q`,
  which needs an actual db value to route a multi-attribute pattern through
  arrangement.query. Composed entirely from kotobase-peer's public API
  (hot-datoms + transact), so it stays correct against novelty without
  kotobase-peer needing its own db-shaped 'hot-db' primitive."
  [get-fn chain]
  (eng/transact (eng/empty-db)
                (map (fn [{:keys [e a v_edn]}] {:s e :p a :o (edn/read-string v_edn)})
                     (eng/hot-datoms get-fn chain))))

(defn do-q
  "`datomic.q` — triple-pattern query. Rebuilds a hot db from snapshot+novelty
  (writes are rarer than the hammered keyed reads this worker fixes; q's
  multi-clause-free triple-pattern scope is already O(graph), unchanged by
  D1) then routes through arrangement.query. body: {:graph :query_edn} where
  query_edn is a `[s p o]` pattern (nil = wildcard).

  `eng/q`'s `visible?` is required (ADR-2607050500: Query is a first-class
  effect) -- this handler has no capability/purpose-scoped redaction wired
  in yet (tracked as ADR-2607050500 Phase 3, not done here), so it passes
  `(constantly true)` explicitly: today's behavior is unchanged (every
  matching quad visible), stated instead of assumed."
  [store {:keys [graph query_edn]}]
  (let [chain ((:head-get store) graph)
        db    (hot-db (:get-fn store) chain)
        pat   (edn/read-string query_edn)]
    {:ok true :graph graph :rows (vec (eng/q db pat (constantly true)))}))

(defn do-pull
  "`datomic.pull` — all attrs of one entity, via hot-datoms (snapshot +
  novelty merge). body: {:graph :entity}."
  [store {:keys [graph entity]}]
  (let [chain ((:head-get store) graph)
        rows  (eng/hot-datoms (:get-fn store) chain {:index :eavt :components [entity]})]
    {:ok true :graph graph :entity entity
     :attrs (reduce (fn [m {:keys [a v_edn]}] (update m a (fnil conj []) v_edn)) {} rows)}))

(defn do-fold
  "`datomic.fold` — compacts a graph's accumulated novelty into a fresh
  indexed snapshot (ADR-2607032430 D1 `fold!`). Not part of the datomic
  surface proper — a maintenance operation a cron/ops caller invokes to keep
  `hot-datoms`/`do-q` reads fast as novelty grows. `:commit` is absent (no
  head write attempted) when there's nothing to fold, so a redundant/no-op
  call is cheap and doesn't perturb the head. Safe to call anytime, including
  concurrently with a transact or with another fold of the same graph — fold!
  is deterministic/content-addressed, so races converge rather than corrupt
  (the CAS layer in the worker shell resolves any actual head contention)."
  [store {:keys [graph]}]
  (let [get-fn (:get-fn store)
        chain ((:head-get store) graph)
        novelty-n (if chain (eng/novelty-size get-fn chain) 0)]
    (if (zero? novelty-n)
      {:ok true :graph graph :folded false}
      (let [new-chain (eng/fold! (:put! store) get-fn chain)]
        ((:head-put! store) graph new-chain)
        {:ok true :graph graph :folded true :commit new-chain :novelty_folded novelty-n}))))

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
      "fold"     (do-fold store body)
      {:ok false :error "MethodNotImplemented" :method method})
    (catch #?(:clj Exception :cljs :default) e
      ;; the R2 trampoline's cache-miss must propagate to with-blocks, NOT be
      ;; swallowed here — re-throw it; only real errors become InternalError.
      (if (:block-miss (ex-data e))
        (throw e)
        {:ok false :error "InternalError"
         :message #?(:clj (.getMessage e) :cljs (.-message e))}))))
