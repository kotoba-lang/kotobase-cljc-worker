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
  "Signal thrown by the sync get-fn on a cache miss; caught by with-blocks."
  [cid]
  (ex-info "block-miss" {::miss cid}))

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
                                   (if-let [cid (::miss (ex-data e))]
                                     {:miss cid}
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
