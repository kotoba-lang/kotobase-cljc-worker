# kotobase-cljc-worker

> **Deployment retired / migration source only.** New externally reachable
> Cloudflare Workers belong to `gftdcojp/net-kotobase`. Reusable runtime and
> security code is being extracted to `kotoba-lang/kotobase-server`; this repo
> accepts only migration, compatibility, and extraction changes until archive.
> Its checked-in Wrangler manifest has no route and disables `workers.dev`.

Filter-honoring CLJC replacement for the deleted-source WASM kotobase datom
worker. The WASM worker **ignored `index` / `components_edn` / `limit`** and
rehydrated + serialised the WHOLE graph on every `datomic.datoms` read — the
"Invalid array buffer length" 500 that OOMs at the 128 MB isolate ceiling as
`yoro-social` grows (root cause: ADR-2607022330 addendum 2).

This worker serves `ai.gftd.apps.kotobase.datomic.{datoms,transact,q,pull,fold}`
on the CLJC `kotobase-peer`, so a filtered read touches only the matching
entity/attr and a write's cost never depends on graph size
(ADR-2607032430 D1 — log-structured write path, replacing the O(graph)
hydrate+rebuild that hit Cloudflare Workers' CPU limit under 2026-07-03's
mass-write load):

- **transact** → `kotobase-peer.core/commit!`: appends the tx quads as ONE
  novelty block. O(|tx_edn|), independent of graph size — never hydrates,
  never rebuilds an index. CACAO-verified (issuer must own the graph),
  byte-exact with the PDS via `kotobase.cacao`.
- **datoms/pull** → `kotobase-peer.core/hot-datoms`: merges the graph's
  last-folded snapshot (range-pruned index-root prefix-seek — `:eavt`/`:aevt`/
  `:avet` + ordered `components` + `limit`) with any pending novelty (bounded,
  decoded in memory). Never misses data written since the last fold. Passes
  `(constantly true)` for `hot-datoms`'s required `visible?` — same
  convention as `q`, below.
- **q** → rebuilds a hot db from snapshot+novelty, routes through
  `arrangement.query` (triple-pattern scope, unchanged). Passes
  `(constantly true)` for `q`'s required `visible?` (ADR-2607050500) —
  no capability/purpose-scoped redaction wired into this worker yet
  (tracked as Phase 3, not silently dropped). `hot-datoms`/`cold-datoms`/
  `datoms` all gained the same required-`visible?` treatment as a Phase 3
  follow-up (`kotobase-peer`'s own PR); this worker passes `(constantly
  true)` there too, for the same reason.
- **fold** → `kotobase-peer.core/fold!`: compacts a graph's novelty into a
  fresh indexed snapshot. NOT part of the datomic surface proper — a
  maintenance operation an authorized cron/ops caller invokes (not
  necessarily the graph owner) to keep reads fast as novelty accumulates.
  Never triggered inline by a transact, so no single write's CPU budget can
  include an O(graph) compaction — that's precisely what broke under load
  before this landed.

Also serves `com.etzhayyim.apps.kotoba.ipns.{head,publish}` (ADR-2607061800)
— a separate NSID family with a genuinely different trust model from the
datomic surface above: **unauthenticated, self-verifying reads** (`head`)
and **signature-gated writes** (`publish`, no CACAO — authority is the
Ed25519 signature over the record itself, checked server-side via
`kotobase.ipns/verify-head` before it ever reaches R2, `401` on failure).
A monotonic `:sequence` CAS (reusing `r2-get-head`/`r2-put-head-if-match`,
the record JSON-stringified as that pair's "chain" string) rejects rollback
with `409`, same as `datomic.transact`'s head-race handling but over a
signed record instead of a commit chain.

**Known lexicon/implementation mismatch** (owner-confirmed, tracked as a
separate follow-up, not silently papered over): `ipns/head.json`'s query
param is documented as `graph` ("Graph CID ... IPNS name is derived from
it"), but no graph-CID→IPNS-name derivation exists anywhere
(`ipns.core/pubkey->name` derives a name from an Ed25519 **pubkey**, not a
graph CID). This worker stores/looks up records keyed by the signed
record's own `:name` field, and the actual query param read is `name`.

## Architecture

- `handler.cljc` — **pure** XRPC dispatch + `tx_edn`→quads (node-tested with an
  in-memory store; no R2/CACAO).
- `r2.cljc` — `with-blocks`, the **block-miss trampoline** bridging R2 (async)
  to the peer library's sync `get-fn`: run the sync read, fetch missing blocks
  from R2, retry. (node-tested by running `cold-datoms` through a
  promise-returning fake.)
- `worker.cljc` — workerd `:esm` entry: fetch handler, CACAO verify, R2-backed
  read (trampoline) and write (buffer new blocks → flush → advance head).

The dep chain (`kotobase-peer`, `arrangement` — formerly two repos,
quad-store + kqe, merged; ADR-2607050700 — `prolly-tree`, `chain`
(renamed from `commit-dag`, ADR-2607050800), `ipld`, `multiformats`,
`dag-cbor`) + `kotobase-client` (CACAO/cid) are consumed as west-sibling
shadow-cljs source-paths (`../<dep>/src`).

## Build / test

```bash
npm install
npm test                       # handler + trampoline (node)
npx shadow-cljs release worker # → out/worker.js (:esm)
```

Private/sealed promotion additionally requires the six-part operational
evidence in [docs/security-production-readiness.md](docs/security-production-readiness.md).
Configured binding names and implementation tests alone are not S2–S5 evidence.

## Deploy — GATED on the yoro-social migration (do NOT flip the route blindly)

The CLJC prolly/chain block format is **incompatible** with the live Rust
WASM R2 data (`kotobase/wasm-staging`), so cutover is a one-time migration, not a
route flip:

1. `wrangler deploy` (workers.dev, `kotobase/cljc` prefix — the old data is
   untouched).
2. Export `yoro-social` from the live worker (`datomic.datoms :eavt`, retry loop —
   ~75 % per attempt today) and `transact` it in, under the new prefix.
3. Parity-diff `datoms`/`q` old-vs-new for the same graph.
4. Move the `kotobase.aozora.app` custom-domain route here; keep the old worker +
   R2 data as rollback.

Residual check before the flip: `datomic.q` here is triple-pattern only
(`arrangement.query`'s scope); audit live `q` callers for `query_edn`
shapes it can't answer.

**Follow-up (perf):** `prolly-tree.core/scan-prefix` walks the whole index tree
(no key-range pruning), so a keyed read still fetches every block of that ONE
index. Range-pruning it to O(path) makes keyed reads touch a handful of blocks —
the difference between "under the ceiling" (this worker) and "fast".

## Deploy #2 — GATED on the ciphertext-seam migration (ADR-2607051000, confirmed 2026-07-07)

**A SECOND, independent migration gate**, layered on top of the one above
(that one moved WASM→CLJC; this one moves plaintext→encrypted-seam within
CLJC). `main` (`f9454dbf`) introduced ADR-2607051000's `blind-fn`/`encrypt-fn`/
`decrypt-fn` seam. Current source also implements a private/sealed versioned
keyring and AEAD profile, while the checked-in deployment remains
`legacy-public`; promotion is gated by the operational evidence above. The seam
is REQUIRED to call the current `kotobase-peer` API
(deploying without it is the "Invalid arity: 4" crash, confirmed live). But
adopting it also changes the novelty-tx-block wire shape to `{"ct": ...}`
(`kotobase-peer.core/put-tx-block!`), which has **no backward-compat reader**
for the plaintext `{"quads": [...]}` blocks the CURRENTLY-DEPLOYED (pre-
adoption) worker has been writing to `kotobase/cljc-v2` this whole time —
confirmed live 2026-07-07: deploying `f9454dbf` broke reading real production
data (`cbor: unexpected end of input`), immediately rolled back.

**Production is deliberately behind git main until this executes** — do not
redeploy this worker without first:

1. Export the operator `yoro-social` graph's current datoms from the LIVE
   (pre-adoption) deploy (`datomic.datoms :eavt`, same export mechanism as
   Deploy #1 above). ~2,743 datoms as of 2026-07-07.
2. `transact` them into a fresh `KOTOBASE_B2_PREFIX` (e.g. `kotobase/cljc-v3`)
   via a build of `f9454dbf` (or later) — same repo, same worker code,
   different prefix, so `kotobase/cljc-v2` stays untouched as rollback.
3. Parity-diff old vs. new (same `datoms`/`q` check as Deploy #1).
4. Only then bump `wrangler.jsonc`'s `KOTOBASE_B2_PREFIX` to the new prefix
   and redeploy to the `kotobase.aozora.app` custom domain.

See ADR-2607051000's "Addendum: adoption attempt + confirmed migration gate
(2026-07-07)" for the full incident writeup.
