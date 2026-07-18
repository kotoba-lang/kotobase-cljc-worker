(ns kotobase.cljc-worker.r2
  "Bridge Cloudflare R2 (async) to the engine's SYNC block reader.

  cold-datoms / hydrate-db walk a prolly-tree through a synchronous
  `(get-fn cid) -> bytes`, but R2 `.get` is a Promise. `with-blocks` runs such a
  sync computation against an in-memory block cache and, on a cache miss, fetches
  the block from R2 and retries — a block-miss trampoline. Correct for any tree
  shape; efficient once the read touches few blocks (prolly-tree prefix pruning,
  the #13 follow-up). Pure enough to test with a promise-returning fake `fetch1`."
  (:require [clojure.string :as str]))

(defn missing-block
  "Signal thrown by the sync get-fn on a cache miss; caught by with-blocks. The
  `:block-miss` marker lets handler/handle re-throw it (rather than swallow it as
  an InternalError) so the trampoline actually sees the miss."
  [cid]
  (ex-info "block-miss" {:block-miss true :cid cid}))

(defn block-miss?
  "True if `e` is the trampoline's cache-miss signal (used by handler/handle to
  re-throw instead of catching)."
  [e]
  (boolean (:block-miss (ex-data e))))

(defn with-blocks
  "Run `(f sync-get)` where `sync-get` reads from an in-memory cache, fetching
  absent blocks via `(fetch1 cid) -> Promise<bytes>` and retrying. Returns a
  Promise of `f`'s result. `f` must be pure/idempotent (it is re-run per miss).

  `f` may return a plain value OR a js/Promise (ADR-2607051000: the engine's
  crypto seam made the handler's reads/writes Promise-returning on cljs) — a
  block-miss can therefore surface either as a SYNC throw from `f` or as a
  REJECTION of `f`'s promise (sync-get called inside a .then continuation),
  and both trampoline the same way. Non-miss failures reject through."
  [fetch1 f]
  (let [cache (atom {})
        sync-get (fn [cid]
                   (if (contains? @cache cid)
                     (get @cache cid)
                     (throw (missing-block cid))))]
    (letfn [(fetch-and-retry [e]
              (if (:block-miss (ex-data e))
                (-> (fetch1 (:cid (ex-data e)))
                    (.then (fn [bytes]
                             (swap! cache assoc (:cid (ex-data e)) bytes)
                             (step))))
                (js/Promise.reject e)))
            (step []
              (try
                (-> (js/Promise.resolve (f sync-get))
                    (.catch fetch-and-retry))
                (catch :default e (fetch-and-retry e))))]
      (step))))

;; ── R2 binding wrappers (workerd) ────────────────────────────────────────────

(defn block-key [prefix cid] (str prefix "blocks/" cid))
(defn head-key  [prefix graph] (str prefix "heads/" (str/replace graph #"[^A-Za-z0-9._:-]" "_")))
(defn ipns-key  [prefix name] (str prefix "ipns/" (str/replace name #"[^A-Za-z0-9._:-]" "_")))

(defn r2-get-bytes
  "→ Promise<Uint8Array|nil> for an R2 object key."
  [^js bucket k]
  (-> (.get bucket k)
      (.then (fn [obj]
               (when obj
                 (-> (.arrayBuffer obj) (.then #(js/Uint8Array. %))))))))

;; ── immutable block memory cache (ADR-2607167000) ────────────────────────────
;; CID-addressed blocks are IMMUTABLE — bytes for a cid can never change, so
;; caching them in isolate memory changes no semantics, only cost (the exact
;; property IPFS caching everywhere rests on). Only the mutable HEAD pointer
;; must be read fresh every request; nothing here ever touches head keys.
;; The isolate persists across requests on a warm Worker, so hot blocks
;; (chain head state nodes, the views block, prolly-tree roots) serve from
;; memory (~0ms) instead of one R2 round trip each — the dominant share of
;; the measured ~1.2s/request unit cost. FIFO byte-budget eviction rides
;; js/Map's insertion order; a fresh isolate just starts cold (correct,
;; slower). nil fetches (block not in R2 YET — e.g. buffered writes not
;; flushed) are NOT cached, so a later read re-checks R2.

(def ^:private block-cache (js/Map.))
(def ^:private block-cache-bytes (atom 0))
(def ^:private block-cache-budget (* 64 1024 1024))

(defn- block-cache-put! [cid ^js bytes]
  (when (and (some? bytes) (not (.has block-cache cid)))
    (.set block-cache cid bytes)
    (swap! block-cache-bytes + (.-length bytes))
    (loop []
      (when (> @block-cache-bytes block-cache-budget)
        (let [oldest (.-value (.next (.keys block-cache)))]
          (when (some? oldest)
            (swap! block-cache-bytes - (.-length (.get block-cache oldest)))
            (.delete block-cache oldest)
            (recur)))))))

(defn cached-block-bytes
  "Promise<Uint8Array|nil> for an immutable block `cid`: isolate-memory cache
  first, R2 on miss (populating the cache on a non-nil result)."
  [^js bucket pfx cid]
  (if (.has block-cache cid)
    (js/Promise.resolve (.get block-cache cid))
    (-> (r2-get-bytes bucket (block-key pfx cid))
        (.then (fn [bytes] (block-cache-put! cid bytes) bytes)))))

(defn r2-put-bytes [^js bucket k ^js bytes] (.put bucket k bytes))

(defn r2-put-if-absent
  "Atomic create-if-absent. → Promise<boolean>."
  [^js bucket k value]
  (let [headers (doto (js/Headers.) (.set "if-none-match" "*"))]
    (-> (.put bucket k value #js {:onlyIf headers})
        (.then boolean))))

(defn r2-get-text
  [^js bucket k]
  (-> (.get bucket k) (.then (fn [obj] (when obj (.text obj))))))

;; ── head pointer: optimistic-concurrency (CAS) read/write ───────────────────
;;
;; A plain (unconditional) head .put races: two overlapping transacts against
;; the SAME graph (the PDS's operator-identity yoro-social graph is shared
;; across every actor's createRecord, so this is the common case, not an edge
;; case — confirmed live 2026-07-03, ADR-2607022330 addendum 3) both read the
;; same prev head, both compute a commit chained off it, and whichever `.put`
;; lands LAST wins — the other's commit becomes an orphan, unreachable from
;; the head chain even though its blocks are still in R2 (nothing is
;; corrupted, just invisible). r2-get-head/r2-put-head-if-match close that
;; race with R2's native conditional-write support (the `onlyIf` option),
;; mirroring HTTP's ETag/If-Match — no Durable Object, no new component.

(defn r2-get-head
  "→ Promise<{:chain string|nil :etag string|nil}> for the graph's head
  pointer. :etag nil when the key doesn't exist yet (first write to a new
  graph) — callers use that to choose the create-if-absent put path."
  [^js bucket k]
  (-> (.get bucket k)
      (.then (fn [^js obj]
               (if (nil? obj)
                 {:chain nil :etag nil}
                 (-> (.text obj) (.then (fn [text] {:chain text :etag (.-etag obj)}))))))))

(defn r2-put-head-if-match
  "Atomic conditional head write. Existing heads use ETag compare-and-swap;
  genesis uses the documented conditional-Headers form `If-None-Match: *`.
  R2 returns nil when a precondition fails. → Promise<boolean>."
  [^js bucket k chain etag]
  (let [only-if (if (nil? etag)
                  (doto (js/Headers.) (.set "if-none-match" "*"))
                  #js {:etagMatches etag})]
    (-> (.put bucket k chain #js {:onlyIf only-if})
        (.then (fn [result] (boolean result))))))
