# Migration-only runtime

This repository is retained to reproduce historical ciphertext, R2 layouts,
authority snapshots and recovery tests. It is not a deploy owner.

Invariants:

- `workers_dev` is false and `routes` is empty;
- `npm run deploy` fails closed;
- no new hostname, production tenant or secret is introduced here;
- public deployment, key custody, authority registry, audit receipts and
  rollback ownership belong to `gftdcojp/net-kotobase`;
- reusable crypto, capability and storage code belongs in focused
  `kotoba-lang` libraries, not in this historical adapter.

The root `wrangler.jsonc` is an inert tombstone with no bindings. Historical
R2 variables and bindings are isolated in `migration/legacy-wrangler.jsonc`;
it is for offline reproduction and recovery exercises only, never normal CI or
deployment.
