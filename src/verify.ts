// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The high-level verify API — the SECURITY-CRITICAL surface. Verifying a VC is
// NOT just "the signature checks out": it is a conjunction of independent gates,
// every one of which must pass, each reported as a distinct structured error so a
// caller can act on the specific failure:
//
//   1. structural   — a well-formed credential with exactly the expected shape
//   2. proof present — at least one proof
//   3. cryptosuite   — a suite is registered for proof.cryptosuite (else fail closed)
//   4. signature     — the proof verifies over the canonical claim bytes
//   5. issuer binding — proof.verificationMethod is controlled by the issuer
//   6. proof purpose  — proof.proofPurpose matches the expected purpose
//   7. validity       — now ∈ [validFrom, validUntil]
//   8. trusted issuer — (optional) the issuer is in the caller's allowlist
//   9. status         — the Bitstring Status List v1.0 revocation/suspension gate
//
// Fail-closed throughout: an unresolvable key, an unknown suite, a malformed
// proofValue, a missing field, an unreachable status list — all become
// `verified: false` with a reason, never a thrown exception or a silent accept.
//
// The per-proof / validity / controller gates live once in src/verify-core.ts
// (shared with the parsed-RDF verifier src/verify-rdf.ts); the status gate lives in
// src/status-list.ts. This file is the structured-credential entry point that wires
// them together.

import type { ControlledByCheck } from "./controller.js";
import { credentialToRdf } from "./credential.js";
import type { ProofVerifyOptions, SuiteRegistry } from "./proof.js";
import { defaultSuiteRegistry } from "./proof.js";
import { checkCredentialStatus } from "./status-list.js";
import type {
  Credential,
  CredentialStatus,
  DataIntegrityProof,
  VerifiableCredential,
  VerificationError,
  VerificationResult,
  VerifyOptions,
} from "./types.js";
import { checkValidityWindow, resolveControlledBy, verifyProofSet } from "./verify-core.js";
import { parseAndVerifyCredential } from "./verify-rdf.js";

/** Options for {@link verifyCredential}: the suite registry + the key resolver. */
export interface VerifyCredentialOptions extends VerifyOptions {
  /**
   * The registry of accepted proof suites. Defaults to the bundled Data Integrity
   * suites (`eddsa-rdfc-2022` + `ecdsa-rdfc-2019`). Register a BBS/JWT/SPARQ-ZK
   * suite to accept those proofs.
   */
  readonly registry?: SuiteRegistry;
  /**
   * Resolve a `verificationMethod` IRI to its public key (suite-specific; the
   * bundled suite wants a WebCrypto public `CryptoKey`). REQUIRED — a verifier
   * with no way to obtain the public key cannot verify anything.
   */
  readonly resolveKey: ProofVerifyOptions["resolveKey"];
  /**
   * Decide whether a `verificationMethod` IRI is controlled by `issuer` (may be
   * async — the default resolves a document). When omitted, the default is:
   *   - if {@link VerifyOptions.fetch} is provided → the DOCUMENT-RESOLVED check
   *     ({@link documentResolvedControlledBy}) — the SAFE default that fetches the
   *     issuer's own authoritative document and confirms it asserts
   *     `<issuer> <verificationRelationship> <verificationMethod>`, where the
   *     relationship matches the expected proof purpose (`sec:assertionMethod` by
   *     default);
   *   - if NO `fetch` is provided → FAIL CLOSED (deny). The unsafe string-prefix
   *     heuristic is NO LONGER the default; import `prefixControlledBy` to opt into
   *     it explicitly (documented unsafe).
   */
  readonly isControlledBy?: ControlledByCheck;
}

/** Normalise one-or-many proofs to an array. */
function proofsOf(vc: VerifiableCredential): DataIntegrityProof[] {
  const proof = vc.proof;
  return Array.isArray(proof)
    ? [...(proof as readonly DataIntegrityProof[])]
    : [proof as DataIntegrityProof];
}

/** Strip the proof to recover the unsigned claim graph the signature covered. */
function unsigned(vc: VerifiableCredential): Credential {
  const { proof: _proof, ...rest } = vc;
  return rest as Credential;
}

/** Normalise one-or-many `credentialStatus` entries to an array (empty if absent). */
function statusEntriesOf(vc: VerifiableCredential): CredentialStatus[] {
  const cs = vc.credentialStatus;
  if (cs === undefined) return [];
  return Array.isArray(cs) ? [...(cs as readonly CredentialStatus[])] : [cs as CredentialStatus];
}

/**
 * Verify a {@link VerifiableCredential}. Returns a {@link VerificationResult}
 * whose `verified` is `true` IFF every gate passed; on failure `errors` lists
 * every distinct reason. Never throws on an invalid credential.
 */
export async function verifyCredential(
  vc: VerifiableCredential,
  options: VerifyCredentialOptions,
): Promise<VerificationResult> {
  const errors: VerificationError[] = [];
  const registry = options.registry ?? defaultSuiteRegistry();
  const now = options.now ?? new Date();
  const expectedPurpose = options.expectedProofPurpose ?? "assertionMethod";
  const controlledBy = resolveControlledBy(options, expectedPurpose);

  // 1. structural
  if (
    vc === null ||
    typeof vc !== "object" ||
    typeof vc.issuer !== "string" ||
    vc.issuer.length === 0 ||
    vc.credentialSubject === undefined
  ) {
    return {
      verified: false,
      errors: [{ code: "MALFORMED", message: "not a well-formed credential" }],
    };
  }
  const issuer = vc.issuer;

  // 2. proof present
  const proofs = vc.proof === undefined ? [] : proofsOf(vc);
  if (proofs.length === 0) {
    errors.push({ code: "NO_PROOF", message: "credential carries no proof" });
  }

  // 7. validity window (independent of any proof)
  errors.push(...checkValidityWindow(now, vc.validFrom, vc.validUntil));

  // 8. trusted issuer (optional allowlist)
  if (options.trustedIssuers !== undefined && !options.trustedIssuers.includes(issuer)) {
    errors.push({ code: "UNTRUSTED_ISSUER", message: `issuer ${issuer} is not trusted` });
  }

  // 3–6: check EACH proof over the canonical claim graph (proof removed).
  errors.push(
    ...(await verifyProofSet({
      documentQuads: credentialToRdf(unsigned(vc)),
      proofs,
      issuer,
      registry,
      controlledBy,
      expectedPurpose,
      resolveKey: options.resolveKey,
    })),
  );

  // 9. Bitstring Status List status gate (revocation / suspension). Skipped only
  // when explicitly disabled (checkStatus === false) — a production verify keeps it
  // on; a skipped revocation check is an accept.
  const statusEntries = statusEntriesOf(vc);
  if (statusEntries.length > 0 && options.checkStatus !== false) {
    errors.push(
      ...(await checkCredentialStatus({
        entries: statusEntries,
        credentialId: typeof vc.id === "string" ? vc.id : undefined,
        issuer,
        now,
        fetch: options.fetch,
        revocationStore: options.revocationStore,
        registry,
        resolveKey: options.resolveKey,
        isControlledBy: options.isControlledBy,
        verifyStatusCredential: parseAndVerifyCredential,
      })),
    );
  }

  return errors.length === 0
    ? { verified: true, errors: [], issuer }
    : { verified: false, errors, issuer };
}
