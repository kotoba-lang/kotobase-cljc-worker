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
                                        do-fold and diagHydrateCost/
                                        diagCommitCost only; a DIRECT R2
                                        fetch, bypassing the with-blocks
                                        sync-retry trampoline entirely --
                                        absent/nil falls back to the with-
                                        blocks-trampolined cold-datoms path
                                        exactly as before this key existed.
                                        See do-fold's, do-diag-hydrate-
                                        cost's, and do-diag-commit-cost's
                                        docstrings.)

  diagCommitCost also uses `:put!` (writing real, content-addressed --
  effectively idempotent when the graph is unchanged -- blocks; see its
  own docstring)."
  (:require #?(:clj  [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            [clojure.string :as str]
            [kotobase.server.security.crypto :as crypto]
            [kotobase-peer.core :as eng]
            [kotobase-peer.policy :as policy]
            [ipld.core :as ipld]
            [prolly-tree.core :as pt]
            [arrangement.core :as qs]))

(def datomic-ns "ai.gftd.apps.kotobase.datomic")
(def kg-ns "ai.gftd.apps.kotobase.kg")

(defn- blind-of [store] (or (:blind-fn store) crypto/blind-fn))
(defn- encrypt-of [store] (or (:encrypt-fn store) crypto/encrypt-fn))
(defn- decrypt-of [store] (or (:decrypt-fn store) crypto/decrypt-fn))

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

(defn- owned-entities
  "Entity ids the viewer OWNS per the policy's :owner-attrs (Phase 3c):
  one narrow :avet [owner-attr viewer-did] scan per owner attr. Empty when
  the policy declares no owner-attrs or the viewer is anonymous. Promise on
  cljs."
  [store chain policy viewer-did]
  (let [owner-attrs (:owner-attrs policy)]
    (if (or (nil? chain) (empty? owner-attrs) (nil? viewer-did))
      #?(:clj #{} :cljs (js/Promise.resolve #{}))
      #?(:clj
         (into #{}
               (mapcat (fn [attr]
                         (->> (eng/hot-datoms (:get-fn store) chain
                                              {:index :avet :components [attr viewer-did]}
                                              (constantly true) (blind-of store) (decrypt-of store)
                                              (:async-get-fn store))
                              (map :e))))
               owner-attrs)
         :cljs
         (-> (js/Promise.all
              (into-array
               (map (fn [attr]
                      (eng/hot-datoms (:get-fn store) chain
                                      {:index :avet :components [attr viewer-did]}
                                      (constantly true) (blind-of store) (decrypt-of store)
                                      (:async-get-fn store)))
                    owner-attrs)))
             (.then (fn [^js lists]
                      (into #{} (mapcat #(map :e %)) (array-seq lists)))))))))

(defn- request-visible?
  "The per-request `visible?` row filter (ADR-2607174500). ONE narrow read
  of the graph's in-chain policy entity, combined with the viewer's
  VERIFIED CACAO capability resources AND (Phase 3c) the entity ids the
  viewer OWNS per the policy's :owner-attrs. A policy-less graph yields
  (constantly true). `viewer` is the auth map {:did :resources} or nil.
  Promise on cljs."
  [store chain viewer]
  (let [caps (:resources viewer)
        viewer-did (:did viewer)]
    (if (nil? chain)
      (let [visible? (policy/visible-for-mode nil caps #{} (:security-mode store))]
        #?(:clj visible? :cljs (js/Promise.resolve visible?)))
      (then* (eng/hot-datoms (:get-fn store) chain
                             {:index :eavt :components [policy/policy-entity]}
                             (constantly true) (blind-of store) (decrypt-of store)
                             (:async-get-fn store))
             (fn [rows]
               (let [policy (policy/policy-of rows)]
                 (then* (owned-entities store chain policy viewer-did)
                        (fn [owned]
                          (policy/visible-for-mode policy caps owned
                                                   (:security-mode store))))))))))

(defn do-datoms
  "`datomic.datoms` — filtered read via hot-datoms (snapshot + novelty merge,
  range-pruned on the snapshot side; never a whole-graph rehydrate). body:
  {:graph :index :components_edn :limit}.

  `eng/hot-datoms`'s `visible?` is required (ADR-2607050500, same reasoning
  as `do-q`'s `eng/q` call below) -- this handler has no capability/purpose-
  scoped redaction wired in yet (ADR-2607050500 Phase 3, not done here), so
  it passes `(constantly true)` explicitly: today's behavior is unchanged,
  stated instead of assumed. `blind-fn`/`decrypt-fn` are the explicit
  plaintext-passthrough profile (`kotobase.server.security.crypto`,
  ADR-2607051000 adoption) — on cljs the response is a `js/Promise`."
  ([store body] (do-datoms store body nil))
  ([store {:keys [graph index components_edn limit]} viewer]
   (let [chain ((:head-get store) graph)]
     (then* (request-visible? store chain viewer)
            (fn [visible?]
              (then* (eng/hot-datoms (:get-fn store) chain
                                     {:index (or (index-kw index) :eavt)
                                      :components (vec components_edn)
                                      :limit limit}
                                     visible? (blind-of store) (decrypt-of store)
                                     (:async-get-fn store))
                     (fn [rows] (merge {:ok true :graph graph :datoms (vec rows)}
                                       (policy/visibility-evidence visible?)))))))))

(defn do-transact
  "`datomic.transact` — append the tx quads as ONE novelty block and advance
  the chain. O(|tx_edn|) — independent of graph size; never hydrates or
  rebuilds an index (ADR-2607032430 D1, replacing the old hydrate+rebuild
  path that hit Cloudflare Workers' CPU limit under mass-write load).
  `auth-did` is the CACAO-verified issuer (the shell verifies it == graph
  owner); nil here means the shell already gated it. `novelty_size` in the
  response is an observability signal for when a `fold` (see `do-fold`) is
  worth invoking — this handler never folds itself."
  [store {:keys [graph tx_edn]} auth]
  (let [get-fn (:get-fn store)
        prev-chain ((:head-get store) graph)
        quads (vec (tx-edn->quads tx_edn))
        context (if (map? auth)
                  auth
                  ;; Trusted embedded/test compatibility only. The network
                  ;; worker always supplies the strict verifier's auth map.
                  {:did auth :effective-caps #{policy/transact-capability
                                               policy/policy-admin-capability}})
        policy-rows (if prev-chain
                      (eng/hot-datoms get-fn prev-chain
                                      {:index :eavt :components [policy/policy-entity]}
                                      (constantly true) (blind-of store) (decrypt-of store)
                                      (:async-get-fn store))
                      #?(:clj [] :cljs (js/Promise.resolve [])))]
    (then* policy-rows
           (fn [rows]
             (policy/assert-write-authorized!
              (policy/policy-of rows) context quads (:security-mode store))
             (then* (eng/commit! (:put! store) get-fn quads prev-chain (encrypt-of store))
                    (fn [chain]
                      ((:head-put! store) graph chain)
                      {:ok true :graph graph :commit chain :previous_commit prev-chain
                       :datom_count (count quads)
                       :novelty_size (eng/novelty-size get-fn chain)}))))))

;; ── kg.ingest / kg.ingest_batch (ai.gftd.apps.kotobase.kg.*, additive) ───────
;; A SEPARATE NSID family from datomic.* above — projects a kg "entity +
;; claims + relations" payload (ai.gftd.apps.kotobase.kg.ingest[_batch]'s own
;; lexicon shape) into the SAME {:s :p :o} quad model tx-edn->quads already
;; produces, then reuses do-transact's own authorization + commit machinery
;; (kg-commit!, factored out below) verbatim — a kg write is exactly as
;; write-gated as a datom write, no separate/weaker policy path.
;;
;; Wire-shape reconciliation (confirmed by reading both real sources, not
;; guessed): the ai.gftd.apps.kotobase.kg.ingest LEXICON documents claims as
;; `{predicate object}` / relations as `{predicate target}` (snake_case
;; entity fields: label_ja/label_en/valid_from/...), but the REAL, live
;; caller (gftdcojp/cloud-itonami's cloud_itonami.kotobase-kg /
;; cloud_itonami.net-kotobase kg-ingest!) sends camelCase claims as
;; `{pred value}` / relations as `{pred dstId}` and camelCase entity fields
;; (labelEn/validFrom/...) — that ns's own docstring: "Field shapes match
;; the PRODUCTION pod structs (kotoba-server KgIngestReq/KgClaim/KgRelation,
;; all serde rename_all=camelCase)". Both are genuinely real, so every
;; field below is read under EITHER spelling (whichever is present),
;; instead of picking one and silently dropping the other's data.
;;
;; Predicate namespacing (kg/claim/<pred>, kg/relation/<pred>) is exactly
;; what cloud_itonami.kotobase-kg's own docstring documents as the target
;; shape ("Predicates land as `kg/claim/<pred>` / `kg/relation/<pred>`
;; quads") — treated as authoritative since it describes what the real
;; caller already expects. `kg/entity/<field>` (entity-level scalar attrs)
;; and `kg/label_vec` (the lexicon's own literal name for the embedding
;; field: "stored as a kg/label_vec VectorF32 quad") are this handler's
;; own, explicitly-stated extensions beyond that docstring — needed so an
;; entity's own type/label/etc. aren't silently discarded (only claims/
;; relations were documented; the entity's own attributes still need
;; SOMEWHERE to live to round-trip through a future kg.query).

(defn- kg-field
  "`entity`'s value for one logical field, trying the camelCase key first
  (the real live caller's wire shape), then the lexicon's snake_case key."
  [entity camel-k snake-k]
  (if (contains? entity camel-k) (get entity camel-k) (get entity snake-k)))

(def ^:private kg-entity-scalar-fields
  "[camel-key snake-key canonical-name] — every ai.gftd.apps.kotobase.kg.ingest
  entity-level scalar field besides :id/:claims/:relations/:label_vec
  (handled separately below), projected as `kg/entity/<canonical-name>`
  quads when present under either spelling."
  [[:type nil "type"]
   [:qid nil "qid"]
   [:labelJa :label_ja "labelJa"]
   [:labelEn :label_en "labelEn"]
   [:confidence nil "confidence"]
   [:license nil "license"]
   [:extractor nil "extractor"]
   [:sourceId :source_id "sourceId"]
   [:validFrom :valid_from "validFrom"]
   [:validTo :valid_to "validTo"]
   [:ingestedAt :ingested_at "ingestedAt"]])

(defn- kg-entity-scalar-quads [entity-id entity]
  (for [[camel-k snake-k canonical] kg-entity-scalar-fields
        :let [v (kg-field entity camel-k snake-k)]
        :when (some? v)]
    {:s entity-id :p (str "kg/entity/" canonical) :o (str v)}))

(defn- kg-label-vec-quads [entity-id entity]
  (let [v (kg-field entity :labelVec :label_vec)]
    (when (some? v)
      [{:s entity-id :p "kg/label_vec" :o (pr-str v)}])))

(defn- kg-claim-quads [entity-id claims]
  (for [c claims
        :let [pred (kg-field c :pred :predicate)
              value (kg-field c :value :object)]
        :when (and (some? pred) (some? value))]
    {:s entity-id :p (str "kg/claim/" pred) :o (str value)}))

(defn- kg-relation-quads [entity-id relations]
  (for [r relations
        :let [pred (kg-field r :pred :predicate)
              target (kg-field r :dstId :target)]
        :when (and (some? pred) (some? target))]
    {:s entity-id :p (str "kg/relation/" pred) :o (str target)}))

(defn kg-entity->quads
  "One ai.gftd.apps.kotobase.kg.ingest entity map → its `{:s :p :o}` quads
  (entity-level scalars + claims + relations — see the section comment
  above for the exact predicate shapes and dual camelCase/snake_case
  field acceptance). Throws on a missing/blank :id — every quad needs a
  subject."
  [entity]
  (let [entity-id (some-> (:id entity) str)]
    (when (str/blank? entity-id)
      (throw (ex-info "kotobase kg: entity :id is required" {:entity entity})))
    (vec (concat (kg-entity-scalar-quads entity-id entity)
                 (kg-label-vec-quads entity-id entity)
                 (kg-claim-quads entity-id (:claims entity))
                 (kg-relation-quads entity-id (:relations entity))))))

(defn kg-subject-cid
  "Content-addressed CID of one kg.ingest entity payload — CIDv1/dag-cbor/
  sha2-256 over `(pr-str entity)` via `ipld/node->block`, the SAME
  primitive `kotobase-peer.policy/policy-cid` already uses for the same
  'stable content identity of an EDN blob' need. A real hash, not a
  fabricated-looking placeholder string."
  [entity]
  (:cid (ipld/node->block {"type" "kotobase/kg-entity/v1" "entity" (pr-str entity)})))

(defn- kg-commit!
  "Shared write path for do-kg-ingest/do-kg-ingest-batch: the SAME
  authorization + commit machinery do-transact uses above (read the
  graph's in-chain policy, policy/assert-write-authorized! against it,
  then eng/commit! + head-put!) — factored out so neither kg entry point
  copy-pastes (and risks silently drifting from) that gate. `quads` is the
  full flattened set for the whole request (one entity or a batch); `auth`
  is do-transact's own `auth` contract unchanged (a verified-CACAO
  {:did :effective-caps ...} context map, or — embedded/test compatibility
  only — a bare did)."
  [store graph quads auth]
  (let [get-fn (:get-fn store)
        prev-chain ((:head-get store) graph)
        context (if (map? auth)
                  auth
                  {:did auth :effective-caps #{policy/transact-capability
                                               policy/policy-admin-capability}})
        policy-rows (if prev-chain
                      (eng/hot-datoms get-fn prev-chain
                                      {:index :eavt :components [policy/policy-entity]}
                                      (constantly true) (blind-of store) (decrypt-of store)
                                      (:async-get-fn store))
                      #?(:clj [] :cljs (js/Promise.resolve [])))]
    (then* policy-rows
           (fn [rows]
             (policy/assert-write-authorized!
              (policy/policy-of rows) context quads (:security-mode store))
             (then* (eng/commit! (:put! store) get-fn quads prev-chain (encrypt-of store))
                    (fn [chain]
                      ((:head-put! store) graph chain)
                      {:chain chain :previous-chain prev-chain}))))))

(defn do-kg-ingest
  "`kg.ingest` — ingest ONE entity (see the section comment above for the
  quad projection). body: {:graph <derived by the caller shell from the
  verified CACAO's own kotoba://graph/<db-name> resource — kg.ingest's own
  wire body carries no :graph/:db_name field at all> ...entity fields}.
  Response mirrors the lexicon: {:ok :subjectCid :quadCount}."
  [store body auth]
  (let [entity (dissoc body :graph :tenant_did :cacao_b64)
        quads (kg-entity->quads entity)
        subject-cid (kg-subject-cid entity)]
    (then* (kg-commit! store (:graph body) quads auth)
           (fn [{:keys [chain previous-chain]}]
             {:ok true :graph (:graph body) :subjectCid subject-cid
              :quadCount (count quads) :commit chain :previous_commit previous-chain}))))

(defn do-kg-ingest-batch
  "`kg.ingest_batch` — ingest MANY entities as one commit (one novelty
  block covering every entity's quads, not one commit per entity — same
  O(|tx|) reasoning as do-transact). body: {:graph <derived, see
  do-kg-ingest> :entities [<kg.ingest-shaped entity> ...]}. Response
  mirrors the lexicon: {:ok :ingested :subjectCids :quadCount}."
  [store {:keys [graph entities]} auth]
  (let [entities (vec entities)
        per-entity (mapv (fn [e] {:quads (kg-entity->quads e) :subject-cid (kg-subject-cid e)})
                         entities)
        quads (vec (mapcat :quads per-entity))]
    (then* (kg-commit! store graph quads auth)
           (fn [{:keys [chain previous-chain]}]
             {:ok true :graph graph :ingested (count entities)
              :subjectCids (mapv :subject-cid per-entity)
              :quadCount (count quads) :commit chain :previous_commit previous-chain}))))

(defn- hot-db
  "The full hot db as of `chain` (snapshot + novelty merged) — for `do-q`,
  which needs an actual db value to route a multi-attribute pattern through
  arrangement.query. Composed entirely from kotobase-peer's public API
  (hot-datoms + transact), so it stays correct against novelty without
  kotobase-peer needing its own db-shaped 'hot-db' primitive.

  Passes `(constantly true)` for `hot-datoms`'s required `visible?` (see
  `do-q`'s own `eng/q` call, below, for why: no capability/purpose-scoped
  redaction is wired into this handler yet, ADR-2607050500 Phase 3)."
  [store chain]
  (then* (eng/hot-datoms (:get-fn store) chain nil (constantly true)
                         (blind-of store) (decrypt-of store) (:async-get-fn store))
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
  ([store body] (do-q store body nil))
  ([store {:keys [graph query_edn]} viewer]
   (let [chain ((:head-get store) graph)
         pat   (edn/read-string query_edn)]
     (then* (request-visible? store chain viewer)
           (fn [visible?]
             (then* (hot-db store chain)
                    (fn [db] (merge {:ok true :graph graph :rows (vec (eng/q db pat visible?))}
                                    (policy/visibility-evidence visible?)))))))))

(defn do-pull
  "`datomic.pull` — all attrs of one entity, via hot-datoms (snapshot +
  novelty merge). body: {:graph :entity}.

  Same `(constantly true)` `visible?` convention as `do-datoms`/`hot-db`,
  above (ADR-2607050500 Phase 3 redaction not wired in yet)."
  ([store body] (do-pull store body nil))
  ([store {:keys [graph entity]} viewer]
   (let [chain ((:head-get store) graph)]
     (then* (request-visible? store chain viewer)
            (fn [visible?]
              (then* (eng/hot-datoms (:get-fn store) chain {:index :eavt :components [entity]}
                                     visible? (blind-of store) (decrypt-of store)
                                     (:async-get-fn store))
                     (fn [rows]
                       (merge {:ok true :graph graph :entity entity
                               :attrs (reduce (fn [m {:keys [a v_edn]}]
                                                (update m a (fnil conj []) v_edn)) {} rows)}
                              (policy/visibility-evidence visible?)))))))))

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
  through that batched-concurrent path instead.

  Optional body `:views_edn` (an EDN string map of view-name →
  {\"attrs\" [attr …]}, or a nil spec to remove that view — ADR-2607166600):
  declares/updates the graph's materialized views, which every fold
  (with or without this param — stored specs carry forward) re-derives from
  the merged db and writes as one content-addressed views block linked from
  the chain state. Served by `datomic.view` (`do-view`). A views_edn call
  against a graph with ZERO novelty still runs a views-only fold (the
  zero-novelty early return is bypassed when views_edn is present, and
  fold! over empty novelty re-commits the identical content-addressed
  snapshot — cheap — while materializing the views): declaring a view on a
  quiet graph works immediately instead of waiting for the next write."
  [store {:keys [graph max_novelty views_edn]}]
  (let [get-fn (:get-fn store)
        chain ((:head-get store) graph)
        novelty-n (if chain (eng/novelty-size get-fn chain) 0)
        max-novelty (when (pos-int? max_novelty) max_novelty)
        views (when (seq views_edn) (edn/read-string views_edn))]
    (if (and (zero? novelty-n) (or (nil? views) (nil? chain)))
      {:ok true :graph graph :folded false}
      (then* (eng/fold! (:put! store) get-fn chain ipld/link? max-novelty
                        (blind-of store) (encrypt-of store) (decrypt-of store)
                        (:cache-get store) (:cache-put! store) (:async-get-fn store)
                        views)
             (fn [new-chain]
               ((:head-put! store) graph new-chain)
               {:ok true :graph graph :folded true :commit new-chain
                :previous_commit chain
                :novelty_folded (if max-novelty (min max-novelty novelty-n) novelty-n)
                :novelty_remaining (if max-novelty (max 0 (- novelty-n max-novelty)) 0)})))))

(defn do-view
  "`datomic.view` — rows of a fold-materialized view (ADR-2607166600),
  always fresh: the views block's rows merged with unfolded novelty
  server-side (eng/view-rows). Body: {:graph :view}. Response mirrors
  do-datoms (`:datoms` rows) so existing row consumers work unchanged;
  `{:ok false :error \"ViewNotFound\"}` when the view was never
  materialized for this graph."
  ([store body] (do-view store body nil))
  ([store {:keys [graph view]} viewer]
   (let [chain ((:head-get store) graph)]
     (then* (request-visible? store chain viewer)
            (fn [visible?]
              (then* (eng/view-rows (:get-fn store) chain view visible? (decrypt-of store))
                     (fn [res]
                       (merge
                        (if res
                          {:ok true :graph graph :view view :spec (:spec res)
                           :datoms (vec (:rows res))}
                          {:ok false :error "ViewNotFound" :graph graph :view view})
                        (policy/visibility-evidence visible?)))))))))

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

(defn do-diag-commit-cost
  "Read-ISH diagnostic (NOT part of the datomic surface; no auth, matching
   diagHydrateCost's precedent -- see the tradeoff note below): measures
   `fold!`'s WRITE side (`qs/commit!`'s 4x `prolly-tree.core/build-tree`
   index rebuild) SEPARATELY from the READ side (`hydrate-db-cached`'s
   walk+decrypt+in-memory-build, already isolated by `diagHydrateCost`).

   Motivation (ADR-2607120730 follow-up, confirmed live): routing `fold!`'s
   hydrate step through `scan-prefix-async` (5130 entries, ~800ms) did NOT
   resolve `yoro-social-v2`'s CPU-exceeded failures -- a cron tick scheduled
   well after that fix deployed still failed with error 1102. `decrypt-fn`
   is confirmed a trivial passthrough (no real crypto yet), ruling out
   decrypt cost. `qs/commit!` rebuilds ALL 4 covering indexes (spo/pso/pos/
   ocp) from scratch via `build-tree`, none of which the read-side fix
   touched -- `build-tree`'s `boundary?` computes a SHA-256 hash
   SYNCHRONOUSLY per entry just to decide chunk boundaries, before any node
   is even built, ×4 indexes. This measures whether THAT is the remaining
   cost.

   DOES actually call `qs/commit!` (via `(:put! store)`), so it pays the
   REAL CPU cost -- but `(:put! store)` is expected to be a BUFFERED,
   in-memory `put!` (never flushed to R2), matching how `fold!`'s own
   `put!` behaves during the real computation (`kotobase-cljc-worker`'s
   `run-write-attempt` also buffers, only flushing blocks to R2 AFTER the
   whole response returns) -- this measures the same CPU-only cost
   production actually pays, not inflated by real write I/O this
   diagnostic doesn't need (nothing ever reads these blocks back, since no
   head is advanced/read). `:cljs` only."
  [store {:keys [graph]}]
  #?(:clj
     {:ok false :error "MethodNotImplemented" :message "diagCommitCost is :cljs-only"}
     :cljs
     (let [chain ((:head-get store) graph)
           get-fn (:get-fn store)
           snap (when chain (eng/latest-snapshot-cid get-fn chain))
           async-get-fn (:async-get-fn store)
           put! (:put! store)]
       (if (nil? chain)
         (js/Promise.resolve {:ok true :graph graph :hydrate_ms 0 :commit_ms 0})
         (let [t0 (js/Date.now)]
           (-> (eng/hydrate-db-cached get-fn snap (blind-of store) (decrypt-of store) nil nil async-get-fn)
               (.then (fn [db]
                        (let [t1 (js/Date.now)]
                          (-> (qs/commit! put! db nil qs/current-schema-version (blind-of store) (encrypt-of store))
                              (.then (fn [_new-snap-cid]
                                       (let [t2 (js/Date.now)]
                                         {:ok true :graph graph :snapshot snap
                                          :hydrate_ms (- t1 t0)
                                          :commit_ms (- t2 t1)})))))))))))))

;; ── dispatch ─────────────────────────────────────────────────────────────────

(defn handle
  "Dispatch a parsed XRPC call. `method` is the NSID suffix after
  `ai.gftd.apps.kotobase.datomic.` (bare, e.g. \"transact\") for the datomic.*
  family, OR the literal compound string \"kg.ingest\"/\"kg.ingest_batch\"
  for the SEPARATE ai.gftd.apps.kotobase.kg.* family (additive — the caller
  shell is responsible for telling the two NSID families apart by URL
  prefix and passing the right `method` spelling; see worker.cljs's
  kg-ns-prefix routing). `body` is the keywordized JSON body; `auth-did` is
  the CACAO-verified issuer or nil. Returns a plain response map; never
  throws for a known method (errors become `{:ok false :error …}`)."
  [store method body auth]
  (letfn [(err [e]
            ;; the R2 trampoline's cache-miss must propagate to with-blocks,
            ;; NOT be swallowed here — re-throw it (on cljs: rejecting the
            ;; response promise, which with-blocks' .catch trampolines); only
            ;; real errors become InternalError.
            (let [data (ex-data e)]
              (cond
                (:block-miss data) (throw e)
                (= :kotobase.policy/write-denied (:type data))
                {:ok false :error "AccessDenied"
                 :reason (some-> data :decision :denials first :reason name)}
                :else {:ok false :error "InternalError"
                       :message #?(:clj (.getMessage ^Exception e)
                                   :cljs (or (ex-message e) (.-message e)))})))]
    (try
      (let [viewer (when (map? auth) auth)
            resp (case method
                   "datoms"   (do-datoms store body viewer)
                   "transact" (do-transact store body auth)
                   "q"        (do-q store body viewer)
                   "pull"     (do-pull store body viewer)
                   "view"     (do-view store body viewer)
                   "fold"     (do-fold store body)
                   "diagHydrateCost" (do-diag-hydrate-cost store body)
                   "diagCommitCost" (do-diag-commit-cost store body)
                   "kg.ingest"       (do-kg-ingest store body auth)
                   "kg.ingest_batch" (do-kg-ingest-batch store body auth)
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
