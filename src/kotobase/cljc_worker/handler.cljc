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
    :head-put!   (fn [graph chain])  -> _ (updates the graph's chain head)
    :cache-get   (fn [key])          -> bytes|nil (OPTIONAL, do-fold only;
                                        memoized-hydration cache read,
                                        ADR-2607120730 Part 1 -- absent/nil
                                        disables caching, no other behavior
                                        change)
    :cache-put!  (fn [key bytes])    -> _ (OPTIONAL, do-fold only; MUST write
                                        through immediately/unbuffered, unlike
                                        :put! -- see eng/hydrate-db-cached's
                                        docstring for why)
    :async-get-fn (fn [cid])         -> js/Promise<bytes|nil> (OPTIONAL,
                                        do-fold and diagHydrateCost only; a
                                        DIRECT R2 fetch, bypassing the
                                        with-blocks sync-retry trampoline
                                        entirely -- absent/nil falls back
                                        to the with-blocks-trampolined
                                        cold-datoms path exactly as before
                                        this key existed. See do-fold's and
                                        do-diag-hydrate-cost's docstrings.)"
  (:require #?(:clj  [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            [clojure.string :as str]
            [kotobase.cljc-worker.crypto :as crypto]
            [kotobase-peer.core :as eng]
            [ipld.core :as ipld]
            [prolly-tree.core :as pt]))

(def datomic-ns "ai.gftd.apps.kotobase.datomic")

(defn- then*
  "Thread `x` through `f` across the engine's platform split (ADR-2607051000:
  kotobase-peer's crypto-touching fns are synchronous values on JVM but
  `js/Promise`s on cljs). On cljs every handler response is therefore a
  Promise — the workerd shell and `r2/with-blocks` both already resolve
  promises, and `js/Promise.resolve` flattens the non-promise case."
  [x f]
  #?(:clj (f x)
     :cljs (.then (js/Promise.resolve x) f)))

;; ── tx_edn (vector of entity maps) → engine quads ────────────────────────────

(defn tx-edn->quads
  "Parse a kotobase `tx_edn` string — a vector of entity maps
  `[{:db/id \"e\" :ns/attr v …} …]` — into `{:s :p :o}` quads. Datafication goes
  through the engine's canonical datom model (`eng/entities->datoms` =
  `datom.core/eavt`), the SAME `[e a v]` representation kgraph (the language's
  in-mem view) speaks — ONE shared datom model across transport, DB, and language
  (ADR-2607032500). Reads the whole string as EDN (no brace-splitting) so map/
  vector values with literal braces are safe (the old tx-edn.mjs brace-split bug).
  `(str :ns/attr)` keeps the leading ':' — PDS datom consumers key on \":ns/attr\".

  Retraction forms (ADR-2607071610 Phase 1) ride the same tx_edn vector:
  `[:db/retract e a v]` → an :op :retract quad, `[:db/retractEntity e]` →
  an :op :retract-entity quad — dispatched BEFORE eavt (which is the pure
  entity-map→[e a v] datafier and stays map-only). Previously these vectors
  reached eavt and 500'd (実測 2026-07-07: PDS deleteRecord「Doesn't support
  name:」の根因)."
  [tx-edn]
  (mapcat (fn [item]
            (cond
              (and (vector? item) (= 4 (count item)) (= :db/retract (first item)))
              (let [[_ e a v] item]
                [{:s (str e) :p (str a) :o (str v) :op :retract}])

              (and (vector? item) (= 2 (count item)) (= :db/retractEntity (first item)))
              [{:s (str (second item)) :op :retract-entity}]

              (map? item)
              (map (fn [[e a v]] {:s (str e) :p (str a) :o (str v)})
                   (eng/entities->datoms [item]))

              :else
              (throw (ex-info "kotobase: unrecognized tx_edn item" {:item item}))))
          (edn/read-string tx-edn)))

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
  {:graph :index :components_edn :limit}.

  `eng/hot-datoms`'s `visible?` is required (ADR-2607050500, same reasoning
  as `do-q`'s `eng/q` call below) -- this handler has no capability/purpose-
  scoped redaction wired in yet (ADR-2607050500 Phase 3, not done here), so
  it passes `(constantly true)` explicitly: today's behavior is unchanged,
  stated instead of assumed. `blind-fn`/`decrypt-fn` are the explicit
  plaintext-passthrough profile (`kotobase.cljc-worker.crypto`,
  ADR-2607051000 adoption) — on cljs the response is a `js/Promise`."
  [store {:keys [graph index components_edn limit]}]
  (let [chain ((:head-get store) graph)]
    (then* (eng/hot-datoms (:get-fn store) chain
                           {:index (or (index-kw index) :eavt)
                            :components (vec components_edn)
                            :limit limit}
                           (constantly true) crypto/blind-fn crypto/decrypt-fn)
           (fn [rows] {:ok true :graph graph :datoms (vec rows)}))))

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
        quads (tx-edn->quads tx_edn)]
    (then* (eng/commit! (:put! store) get-fn quads prev-chain crypto/encrypt-fn)
           (fn [chain]
             ((:head-put! store) graph chain)
             {:ok true :graph graph :commit chain
              :datom_count (count quads)
              :novelty_size (eng/novelty-size get-fn chain)}))))

(defn- hot-db
  "The full hot db as of `chain` (snapshot + novelty merged) — for `do-q`,
  which needs an actual db value to route a multi-attribute pattern through
  arrangement.query. Composed entirely from kotobase-peer's public API
  (hot-datoms + transact), so it stays correct against novelty without
  kotobase-peer needing its own db-shaped 'hot-db' primitive.

  Passes `(constantly true)` for `hot-datoms`'s required `visible?` (see
  `do-q`'s own `eng/q` call, below, for why: no capability/purpose-scoped
  redaction is wired into this handler yet, ADR-2607050500 Phase 3)."
  [get-fn chain]
  (then* (eng/hot-datoms get-fn chain (constantly true)
                         crypto/blind-fn crypto/decrypt-fn)
         (fn [rows]
           (eng/transact (eng/empty-db)
                         (map (fn [{:keys [e a v_edn]}] {:s e :p a :o (edn/read-string v_edn)})
                              rows)))))

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
        pat   (edn/read-string query_edn)]
    (then* (hot-db (:get-fn store) chain)
           (fn [db] {:ok true :graph graph :rows (vec (eng/q db pat (constantly true)))}))))

(defn do-pull
  "`datomic.pull` — all attrs of one entity, via hot-datoms (snapshot +
  novelty merge). body: {:graph :entity}.

  Same `(constantly true)` `visible?` convention as `do-datoms`/`hot-db`,
  above (ADR-2607050500 Phase 3 redaction not wired in yet)."
  [store {:keys [graph entity]}]
  (let [chain ((:head-get store) graph)]
    (then* (eng/hot-datoms (:get-fn store) chain {:index :eavt :components [entity]}
                           (constantly true) crypto/blind-fn crypto/decrypt-fn)
           (fn [rows]
             {:ok true :graph graph :entity entity
              :attrs (reduce (fn [m {:keys [a v_edn]}] (update m a (fnil conj []) v_edn)) {} rows)}))))

(defn do-fold
  "`datomic.fold` — compacts a graph's accumulated novelty into a fresh
  indexed snapshot (ADR-2607032430 D1 `fold!`). Not part of the datomic
  surface proper — a maintenance operation a cron/ops caller invokes to keep
  `hot-datoms`/`do-q` reads fast as novelty grows. `:commit` is absent (no
  head write attempted) when there's nothing to fold, so a redundant/no-op
  call is cheap and doesn't perturb the head. Safe to call anytime, including
  concurrently with a transact or with another fold of the same graph — fold!
  is deterministic/content-addressed, so races converge rather than corrupt
  (the CAS layer in the worker shell resolves any actual head contention).

  Optional body `:max_novelty` (a positive int) bounds the fold to the
  OLDEST that-many not-yet-folded tx blocks (kotobase-peer#16's
  `fold!`/`take-oldest-novelty`) instead of the unbounded default —
  gftdcojp/app-aozora#78: a backlog large enough that even one bounded-
  concurrency fold pass exceeds one Worker invocation's CPU/wall-time
  budget can leave an unbounded fold unable to ever complete. A cron/ops
  caller can pass a small `:max_novelty` and call repeatedly to make
  guaranteed forward progress against such a backlog. Omitted/nil is
  unbounded — identical to pre-existing behavior.

  `:max_novelty` alone doesn't help once the EXISTING indexed snapshot
  itself is too large to hydrate within one Worker's CPU budget — every
  attempt pays that O(graph_shard) cost regardless of how small a novelty
  slice it's folding (ADR-2607120730's root-cause diagnosis, confirmed
  live: yoro-social-v2's fold kept failing with Cloudflare error 1102 even
  bounded to 200). `(:cache-get store)`/`(:cache-put! store)` (both
  optional in `store` — absent/nil disables this, unbounded `:max_novelty`-
  only behavior unchanged) thread through to `eng/fold!`'s memoized-
  hydration arity (ADR-2607120730 Part 1): a retry against the SAME still-
  unfolded snapshot skips the expensive decrypt-and-scan and hits the
  cache instead, so repeated failing cron ticks stop each re-paying the
  full hydrate cost for zero progress.

  `(:async-get-fn store)` (optional, absent/nil falls back exactly to the
  pre-existing behavior) threads through to `eng/fold!`'s async-scan arity
  (ADR-2607120730 follow-up): confirmed live against `yoro-social-v2`'s
  real stuck backlog that neither `:max_novelty` nor `:cache-get`/`:cache-
  put!` actually fix the CPU-exceeded failures, because BOTH only bound or
  skip work AROUND the hydrate step — the hydrate itself, run over the
  `with-blocks` sync-retry trampoline, is O(N^2) in the number of distinct
  blocks touched (one-miss-discovered-per-retry re-walks and re-decodes
  every already-fetched node), independent of graph size. A `diagHydrate
  Cost` probe using `prolly-tree.core/scan-prefix-async` walked the same
  5130-entry snapshot in 806ms. `:async-get-fn` routes the hydrate itself
  through that batched-concurrent path instead."
  [store {:keys [graph max_novelty]}]
  (let [get-fn (:get-fn store)
        chain ((:head-get store) graph)
        novelty-n (if chain (eng/novelty-size get-fn chain) 0)
        max-novelty (when (pos-int? max_novelty) max_novelty)]
    (if (zero? novelty-n)
      {:ok true :graph graph :folded false}
      (then* (eng/fold! (:put! store) get-fn chain ipld/link? max-novelty
                        crypto/blind-fn crypto/encrypt-fn crypto/decrypt-fn
                        (:cache-get store) (:cache-put! store) (:async-get-fn store))
             (fn [new-chain]
               ((:head-put! store) graph new-chain)
               {:ok true :graph graph :folded true :commit new-chain
                :novelty_folded (if max-novelty (min max-novelty novelty-n) novelty-n)
                :novelty_remaining (if max-novelty (max 0 (- novelty-n max-novelty)) 0)})))))

(defn do-diag-hydrate-cost
  "Read-only diagnostic (NOT part of the datomic surface, no write, no fold,
   no risk to the graph): reports how many leaf entries the graph's current
   indexed snapshot's full `:eavt` tree holds, and how long a batched-
   concurrent walk of it takes.

   Measures the suspected dominant contributor to `fold!`'s `hydrate-db`
   exceeding a Worker's CPU budget (gftdcojp/app-aozora#78, ADR-2607120730
   follow-up): `scan-prefix` run over the `with-blocks` sync-retry
   trampoline re-walks and re-decodes every already-fetched node on every
   retry (O(N^2) for a tree touching N distinct blocks), independent of
   whether the tree is simply too large in absolute terms. This uses
   `prolly-tree.core/scan-prefix-async` with `(:async-get-fn store)` — a
   DIRECT R2 fetch that bypasses `with-blocks` entirely — so the numbers
   this returns isolate walk+decode cost from that retry-inflation, letting
   a real production run distinguish \"N itself is too large\" from \"the
   discovery strategy is quadratic.\" Does NOT decrypt/hydrate/build a db;
   `:entry_count` is a raw leaf-entry count, not decoded quad values.
   `:cljs` only (`scan-prefix-async` doesn't exist on `:clj` — this
   diagnostic exists to measure a Worker/R2-latency-specific retry-
   inflation problem that has no JVM analog)."
  [store {:keys [graph]}]
  #?(:clj
     {:ok false :error "MethodNotImplemented" :message "diagHydrateCost is :cljs-only"}
     :cljs
     (let [chain ((:head-get store) graph)
           snap (when chain (eng/latest-snapshot-cid (:get-fn store) chain))
           root-cid (when snap
                      (some-> (get-in (ipld/decode ((:get-fn store) snap)) ["index-roots" "spo"])
                              ipld/link-cid))
           async-get-fn (:async-get-fn store)]
       (if (nil? root-cid)
         (js/Promise.resolve {:ok true :graph graph :snapshot snap :entry_count 0 :elapsed_ms 0})
         (let [start (js/Date.now)]
           (then* (pt/scan-prefix-async async-get-fn root-cid "")
                  (fn [rows]
                    {:ok true :graph graph :snapshot snap
                     :entry_count (count rows)
                     :elapsed_ms (- (js/Date.now) start)})))))))

;; ── dispatch ─────────────────────────────────────────────────────────────────

(defn handle
  "Dispatch a parsed XRPC call. `method` is the NSID suffix after
  `ai.gftd.apps.kotobase.datomic.`; `body` is the keywordized JSON body;
  `auth-did` is the CACAO-verified issuer or nil. Returns a plain response map;
  never throws for a known method (errors become `{:ok false :error …}`)."
  [store method body auth-did]
  (letfn [(err [e]
            ;; the R2 trampoline's cache-miss must propagate to with-blocks,
            ;; NOT be swallowed here — re-throw it (on cljs: rejecting the
            ;; response promise, which with-blocks' .catch trampolines); only
            ;; real errors become InternalError.
            (if (:block-miss (ex-data e))
              (throw e)
              {:ok false :error "InternalError"
               :message #?(:clj (.getMessage ^Exception e)
                           :cljs (or (ex-message e) (.-message e)))}))]
    (try
      (let [resp (case method
                   "datoms"   (do-datoms store body)
                   "transact" (do-transact store body auth-did)
                   "q"        (do-q store body)
                   "pull"     (do-pull store body)
                   "fold"     (do-fold store body)
                   "diagHydrateCost" (do-diag-hydrate-cost store body)
                   {:ok false :error "MethodNotImplemented" :method method})]
        ;; ADR-2607051000: on cljs the do-* fns return js/Promises (the
        ;; engine's crypto seam is Promise-based there) — async failures
        ;; surface as rejections, which the sync try/catch can't see.
        #?(:clj resp
           :cljs (.catch (js/Promise.resolve resp) err)))
      (catch #?(:clj Exception :cljs :default) e
        ;; A do-* fn that throws SYNCHRONOUSLY (before ever returning a
        ;; value/Promise -- e.g. do-transact's tx-edn->quads or do-q's
        ;; pattern parse, both `edn/read-string` on externally-supplied
        ;; EDN) skips the `case` result entirely and lands here,
        ;; bypassing the `.catch (js/Promise.resolve resp) ...` wrapping
        ;; above. Without this being Promise-wrapped too, `handle` would
        ;; return a PLAIN map on this path instead of the Promise every
        ;; cljs caller's `.then` assumes `handle` always returns --
        ;; `TypeError: ...handle(...).then is not a function`, not a
        ;; clean error, on the live production write path (a malformed
        ;; tx_edn from any caller).
        #?(:clj (err e)
           :cljs (js/Promise.resolve (err e)))))))
