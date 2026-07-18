# Kotobase private/sealed production readiness

This runbook defines the evidence required before a deployment may claim ADR
levels S2 through S5. Passing unit tests are implementation evidence, not
production evidence. Store the results in an immutable change ticket or signed
release attestation. Never include secrets, unwrapped keyrings, credentials, or
protected plaintext.

## Promotion invariants

- Record the deployed artifact digest and source revision.
- Set `KOTOBASE_SECURITY_MODE` to `private` or `sealed`; `legacy-public` is not
  a security promotion.
- Exercise every binding against the target environment, not only a mock.
- Require a second operator to review tenant, prefix, signer DID, key IDs, and
  rollback target.
- Block promotion when evidence is absent, stale, or irreproducible.

## 1. Authority registry (S2)

`AUTHORITY_REGISTRY.snapshot(tenant)` returns a versioned, authenticated
snapshot of trusted root DIDs, revoked DIDs, and revoked credential CIDs.
Evidence contains the binding identity, tenant, snapshot version/content
digest, root fingerprints, and request IDs proving: allow, wrong-root deny,
revoked-DID deny, revoked-grant deny, cross-tenant deny, and unavailable/stale
registry fail-closed behavior.

Exercise a live delegated read and write, revoke the leaf grant, refresh the
snapshot, and prove the same credential is denied. Restoration uses a new
registry version; historical evidence is immutable.

## 2. KMS and wrapped keyring (S4)

Private/sealed startup receives `KOTOBASE_WRAPPED_KEYRING_JSON` and unwraps it
through `KEY_UNWRAPPER.unwrap(envelope, tenant)`. Production must not enable
`KOTOBASE_ALLOW_UNWRAPPED_KEYRING` or expose an HPKE private key to the
application when a KMS binding exists.

Evidence records the KMS resource ID, tenant, wrapped-envelope digest, active
key ID, retained decrypt-only key IDs, successful unwrap authorization,
wrong-tenant denial, unavailable-KMS startup failure, and rotation ticket. It
never records AEAD/blind keys or the unwrapped keyring.

Rotation drill:

1. Add a fresh key ID; retain the old key for reads.
2. Write and read a canary under the new active key.
3. Re-encrypt/reindex all reachable blocks and prove logical parity.
4. Prove no reachable envelope refers to the old key ID.
5. Retire the old key, then repeat read/query/audit verification and restore.

## 3. Audit key and external receipt verification (S5)

Provision `KOTOBASE_AUDIT_SEED_B64` as a secret or use an HSM/KMS signer.
Publish its audit signer DID through a separately controlled deployment
manifest. The external verifier pins that DID; accepting only the signer
embedded in a receipt is non-conforming.

For allow, deny, invalid-request, and internal-error canaries, archive the
receipt CID, ciphertext object version/digest, independent replica location,
pinned signer DID/key version, and results for CID recomputation, decrypt,
signature, tenant/graph, operation, outcome, policy CID, request digest, and
previous/new head checks.

Tampered bytes, substituted signer, wrong tenant/keyring, and missing receipt
must fail. Run the verifier outside the serving Worker against a read-only
receipt replica with decrypt permission scoped to audit receipts.

## 4. Migration evidence

Never migrate in place. Freeze or snapshot the source head and run
`migration/reencrypt-graph` into a fresh tenant prefix. It rehydrates the target
and compares logical datoms before returning its blocks/head.

Record source/target tenant and prefix, source/target head CID, block counts,
logical-datom digest/count, active key ID, policy CID, tool/source revision,
start/end time, and parity result. Canary queries cover protected joins,
aggregates, pull, history, denied writes, and audit receipts. Promote routing or
head metadata only after parity succeeds.

## 5. Recovery drill

Keep the source prefix and previous wrapped keyring read-only through the
recovery window. Per release/key rotation, exercise:

1. loss of the current Worker deployment;
2. unavailable registry and KMS, proving fail-closed behavior;
3. restore of registry snapshot, wrapped keyring, policy head, graph head, and
   receipt replica into an isolated environment;
4. verified CID traversal and logical parity against the migration digest;
5. receipt verification with the pinned signer DID; and
6. rollback to the recorded prior prefix without overwriting either history.

Record RPO/RTO, object versions, restored head/policy/key IDs, parity and
receipt results, defects found, remediation, and reviewer approval.

## Evidence record

Use one record per target deployment:

```edn
{:schema "kotobase/security-promotion-evidence/v1"
 :tenant "..." :environment "production"
 :source-revision "..." :artifact-digest "sha256:..."
 :security-mode :private
 :authority {:binding "..." :snapshot-version "..." :digest "sha256:..."
             :tests {:allow "..." :wrong-root-deny "..."
                     :revoked-grant-deny "..." :unavailable-deny "..."}}
 :keyring {:kms-resource "..." :envelope-digest "sha256:..."
           :active-key-id "..." :retained-key-ids ["..."]
           :wrong-tenant-deny "..." :unavailable-deny "..."}
 :audit {:pinned-signer-did "did:key:..." :key-version "..."
         :allow-receipt-cid "..." :deny-receipt-cid "..."
         :external-verification "..." :tamper-deny "..."
         :wrong-signer-deny "..."}
 :migration {:source-prefix "..." :target-prefix "..."
             :source-head "..." :target-head "..."
             :logical-datom-digest "sha256:..." :parity true}
 :recovery {:drill-id "..." :rpo-seconds 0 :rto-seconds 0
            :restore-parity true :receipt-verification true}
 :review {:operator "..." :reviewer "..." :ticket "..."
          :completed-at "..."}}
```

Placeholders or secrets invalidate the record. Until a complete record exists
for the target environment, it remains unpromoted regardless of test results.
