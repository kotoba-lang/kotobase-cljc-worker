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
  Promise of `f`'s result. `f` must be pure/idempotent (it is re-run per miss)."
  [fetch1 f]
  (let [cache (atom {})
        sync-get (fn [cid]
                   (if (contains? @cache cid)
                     (get @cache cid)
                     (throw (missing-block cid))))]
    (letfn [(step []
              (let [outcome (try {:done (f sync-get)}
                                 (catch :default e
                                   (if (:block-miss (ex-data e))
                                     {:miss (:cid (ex-data e))}
                                     {:error e})))]
                (cond
                  (contains? outcome :done)  (js/Promise.resolve (:done outcome))
                  (contains? outcome :error) (js/Promise.reject (:error outcome))
                  :else (-> (fetch1 (:miss outcome))
                            (.then (fn [bytes]
                                     (swap! cache assoc (:miss outcome) bytes)
                                     (step)))))))]
      (step))))

;; ── R2 binding wrappers (workerd) ────────────────────────────────────────────

(defn block-key [prefix cid] (str prefix "blocks/" cid))
(defn head-key  [prefix graph] (str prefix "heads/" (str/replace graph #"[^A-Za-z0-9._:-]" "_")))

(defn r2-get-bytes
  "→ Promise<Uint8Array|nil> for an R2 object key."
  [^js bucket k]
  (-> (.get bucket k)
      (.then (fn [obj]
               (when obj
                 (-> (.arrayBuffer obj) (.then #(js/Uint8Array. %))))))))

(defn r2-put-bytes [^js bucket k ^js bytes] (.put bucket k bytes))

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
  "Conditional head write: succeeds only if the key's CURRENT etag still
  equals `etag` (R2's onlyIf.etagMatches — a native compare-and-swap, no
  read-modify-write gap). `etag` nil means \"only if the key does NOT yet
  exist\" (etagMatches \"\" — R2 has no wildcard absence match, so the empty
  string is used as a value no real object etag can ever equal, giving the
  same create-if-absent effect for the narrow first-write-to-a-new-graph
  race). → Promise<boolean> (true = written, false = lost the race — caller
  must re-read the now-current head and retry)."
  [^js bucket k chain etag]
  (-> (.put bucket k chain
           #js {:onlyIf #js {:etagMatches (or etag "")}})
      (.then (fn [result] (boolean result)))))
