// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The SHARED, single-implementation verification primitives used by BOTH the
// structured-credential verify ({@link verifyCredential}, src/verify.ts) and the
// parsed-RDF verify ({@link parseAndVerifyCredential}, src/verify-rdf.ts). Keeping
// these gates in ONE place means a reviewer audits the fail-closed proof / validity /
// controller / purpose checks once, not twice.

import type { Quad } from "@rdfjs/types";
import type { ControlledByCheck } from "./controller.js";
import { documentResolvedControlledBy } from "./controller.js";
import type { FetchPort } from "./fetch-port.js";
import type { ProofSuite, ProofVerifyOptions, SuiteRegistry } from "./proof.js";
import type { DataIntegrityProof, VerificationError } from "./types.js";

/** The controller-check selection inputs shared by both verify entry points. */
export interface ControllerSelection {
  readonly isControlledBy?: ControlledByCheck;
  readonly fetch?: FetchPort;
}

/** Select the controller check: explicit override → document-resolved (if fetch) → fail-closed. */
export function resolveControlledBy(
  options: ControllerSelection,
  expectedPurpose: string,
): ControlledByCheck {
  if (options.isControlledBy !== undefined) return options.isControlledBy;
  if (options.fetch !== undefined) {
    return documentResolvedControlledBy(options.fetch, expectedPurpose);
  }
  return () => false; // no override and no fetch → cannot resolve control → deny.
}

/** Strip a bare `proofPurpose` token to compare regardless of IRI vs short form. */
export function normalizePurpose(purpose: string): string {
  const hash = purpose.lastIndexOf("#");
  return hash === -1 ? purpose : purpose.slice(hash + 1);
}

/**
 * The validity-window gate (VC-DM 2.0 §"Validity Period"): `now ≥ validFrom` and,
 * when present, `now ≤ validUntil`. An unparseable date is ignored (not fatal) —
 * matching the structured verifier's long-standing behaviour. Pure over plain data.
 */
export function checkValidityWindow(
  now: Date,
  validFrom: string | undefined,
  validUntil: string | undefined,
): VerificationError[] {
  const errors: VerificationError[] = [];
  if (validUntil !== undefined) {
    const until = Date.parse(validUntil);
    if (!Number.isNaN(until) && now.getTime() > until) {
      errors.push({ code: "EXPIRED", message: `credential expired at ${validUntil}` });
    }
  }
  if (validFrom !== undefined) {
    const from = Date.parse(validFrom);
    if (!Number.isNaN(from) && now.getTime() < from) {
      errors.push({ code: "NOT_YET_VALID", message: `credential not valid before ${validFrom}` });
    }
  }
  return errors;
}

/** Inputs to {@link verifyProofSet}: the canonical document quads + the checks. */
export interface ProofSetInput {
  readonly documentQuads: readonly Quad[];
  readonly proofs: readonly DataIntegrityProof[];
  readonly issuer: string;
  readonly registry: SuiteRegistry;
  readonly controlledBy: ControlledByCheck;
  readonly expectedPurpose: string;
  readonly resolveKey: ProofVerifyOptions["resolveKey"];
}

/**
 * Gates 3–6 over EVERY proof (a multi-proof credential requires all valid): registered
 * cryptosuite, matching proof purpose, issuer→verification-method controller binding,
 * and a signature over the canonical `documentQuads`. Fail-closed throughout — an
 * unknown suite, an uncontrolled key, a bad purpose, or a throwing suite all become a
 * distinct structured error, never a silent accept.
 */
export async function verifyProofSet(input: ProofSetInput): Promise<VerificationError[]> {
  const errors: VerificationError[] = [];
  for (const proof of input.proofs) {
    // Fail CLOSED on a malformed proof (missing/mistyped required fields) rather than
    // throwing downstream (e.g. `normalizePurpose(undefined)`). Covers every verify
    // path that funnels through here.
    if (!isWellFormedProof(proof)) {
      errors.push({
        code: "INVALID_SIGNATURE",
        message: "malformed proof (missing required fields)",
      });
      continue;
    }
    const suite = input.registry.get(proof.cryptosuite);
    if (suite === undefined) {
      errors.push({
        code: "UNKNOWN_CRYPTOSUITE",
        message: `no registered suite for cryptosuite "${proof.cryptosuite}"`,
      });
      continue;
    }
    if (normalizePurpose(proof.proofPurpose) !== normalizePurpose(input.expectedPurpose)) {
      errors.push({
        code: "PROOF_PURPOSE_MISMATCH",
        message: `proofPurpose "${proof.proofPurpose}" != expected "${input.expectedPurpose}"`,
      });
    }
    let controlled: boolean;
    try {
      controlled = await input.controlledBy(proof.verificationMethod, input.issuer);
    } catch {
      controlled = false;
    }
    if (!controlled) {
      errors.push({
        code: "ISSUER_MISMATCH",
        message: `verificationMethod ${proof.verificationMethod} is not controlled by issuer ${input.issuer}`,
      });
    }
    if (!(await verifyOneProof(suite, input.documentQuads, proof, input.resolveKey))) {
      errors.push({
        code: "INVALID_SIGNATURE",
        message: `signature did not verify for proof (${proof.cryptosuite})`,
      });
    }
  }
  return errors;
}

/** Whether `proof` carries the string fields the pipeline dereferences (fail-closed guard). */
function isWellFormedProof(proof: DataIntegrityProof): boolean {
  return (
    proof !== null &&
    typeof proof === "object" &&
    typeof proof.cryptosuite === "string" &&
    typeof proof.verificationMethod === "string" &&
    typeof proof.proofPurpose === "string" &&
    typeof proof.proofValue === "string"
  );
}

/** Verify one proof through its suite, mapping any throw to a fail-closed `false`. */
async function verifyOneProof(
  suite: ProofSuite,
  documentQuads: readonly Quad[],
  proof: DataIntegrityProof,
  resolveKey: ProofVerifyOptions["resolveKey"],
): Promise<boolean> {
  try {
    return await suite.verify(documentQuads, proof, { resolveKey });
  } catch {
    return false;
  }
}
