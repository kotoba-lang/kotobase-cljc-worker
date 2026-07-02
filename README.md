# kotobase-cljc-worker

Filter-honoring CLJC replacement for the deleted-source WASM kotobase datom
worker. The WASM worker **ignored `index` / `components_edn` / `limit`** and
rehydrated + serialised the WHOLE graph on every `datomic.datoms` read — the
"Invalid array buffer length" 500 that OOMs at the 128 MB isolate ceiling as
`yoro-social` grows (root cause: ADR-2607022330 addendum 2).

This worker serves `ai.gftd.apps.kotobase.datomic.{datoms,transact,q,pull}` on
the CLJC `kotobase-engine`, so a filtered read touches only the matching
entity/attr:

- **datoms** → `kotobase-engine.core/cold-datoms`: decode the graph's snapshot
  index-roots, prefix-seek the ONE index the query needs (`:eavt`/`:aevt`/`:avet`
  + ordered `components` + `limit`). Never rehydrates the whole db.
- **transact** → `hydrate-db` (one index, ~1×) → assert → `commit!` → advance
  head. CACAO-verified (issuer must own the graph), byte-exact with the PDS via
  `kotobase.cacao`.
- **q/pull** → hydrate then route through kqe / fold entity attrs.

## Architecture

- `handler.cljc` — **pure** XRPC dispatch + `tx_edn`→quads (node-tested with an
  in-memory store; no R2/CACAO).
- `r2.cljc` — `with-blocks`, the **block-miss trampoline** bridging R2 (async)
  to the engine's sync `get-fn`: run the sync read, fetch missing blocks from R2,
  retry. (node-tested by running `cold-datoms` through a promise-returning fake.)
- `worker.cljc` — workerd `:esm` entry: fetch handler, CACAO verify, R2-backed
  read (trampoline) and write (buffer new blocks → flush → advance head).

The engine dep chain (kotobase-engine, kqe, quad-store, prolly-tree, commit-dag,
ipld, multiformats, dag-cbor) + `kotobase-client` (CACAO/cid) are consumed as
west-sibling shadow-cljs source-paths (`../<dep>/src`).

## Build / test

```bash
npm install
npm test                       # handler + trampoline (node)
npx shadow-cljs release worker # → out/worker.js (:esm)
```

## Deploy — GATED on the yoro-social migration (do NOT flip the route blindly)

The CLJC prolly/commit-dag block format is **incompatible** with the live Rust
WASM R2 data (`kotobase/wasm-staging`), so cutover is a one-time migration, not a
route flip:

1. `wrangler deploy` (workers.dev, `kotobase/cljc` prefix — the old data is
   untouched).
2. Export `yoro-social` from the live worker (`datomic.datoms :eavt`, retry loop —
   ~75 % per attempt today) and `transact` it in, under the new prefix.
3. Parity-diff `datoms`/`q` old-vs-new for the same graph.
4. Move the `kotobase.aozora.app` custom-domain route here; keep the old worker +
   R2 data as rollback.

Residual check before the flip: `datomic.q` here is triple-pattern only (kqe
scope); audit live `q` callers for `query_edn` shapes kqe can't answer.

**Follow-up (perf):** `prolly-tree.core/scan-prefix` walks the whole index tree
(no key-range pruning), so a keyed read still fetches every block of that ONE
index. Range-pruning it to O(path) makes keyed reads touch a handful of blocks —
the difference between "under the ceiling" (this worker) and "fast".
