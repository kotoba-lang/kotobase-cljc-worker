(ns kotobase.cljc-worker.crypto
  "EXPLICIT plaintext-passthrough profile for kotobase-peer's REQUIRED
  `blind-fn`/`encrypt-fn`/`decrypt-fn` seam (ADR-2607051000, accepted
  2026-07-06 — the engine takes these with NO silent default, so every
  caller states its at-rest crypto posture instead of assuming one; same
  convention as the handler's explicit `(constantly true)` `visible?`).

  This profile keeps at-rest bytes PLAINTEXT — behaviorally identical to the
  pre-seam worker, chosen deliberately as the adoption step's interim:
  real per-graph keys (HPKE-wrapped DEKs, HMAC blind tokens, AES-256-GCM via
  `crypto.subtle`) are ADR-2607051000's own follow-up and land as a swap of
  THESE three fns, nothing else. All three are trivially deterministic,
  which `fold!` requires of `encrypt-fn` (content-addressed convergence).

  Platform split (kotobase-peer's contract): synchronous values on JVM,
  `js/Promise`s on cljs (where the real implementations will be
  `crypto.subtle` calls, which are Promise-only)."
  (:refer-clojure :exclude []))

(defn blind-fn
  "Index-component blind token (keyed MAC in the real profile). Passthrough:
  the component itself, so prolly-tree leaf keys/prefix seeks stay the
  plaintext `pr-str` encoding."
  [component]
  #?(:clj component :cljs (js/Promise.resolve component)))

(defn encrypt-fn
  "Whole-payload AEAD in the real profile. Passthrough: the plaintext bytes."
  [bytes]
  #?(:clj bytes :cljs (js/Promise.resolve bytes)))

(defn decrypt-fn
  "Inverse of `encrypt-fn`. Passthrough: the stored bytes."
  [bytes]
  #?(:clj bytes :cljs (js/Promise.resolve bytes)))
