### Unreleased

Breaking changes:
 * ABI coder: Remove v1 support. All contracts use ABI coder v2; `pragma abicoder v1` is rejected.

Bugfixes:
 * Test host: Verify real ML-DSA-87 signatures and reject weak public keys, matching go-qrl.
 * SMTChecker: Apply digest conversions to `bytes64` when modeling `mldsa87verify`, preventing incorrect proofs and errors on string literals.

### 0.8.24
