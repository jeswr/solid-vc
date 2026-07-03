import type { Quad } from "@rdfjs/types";
import type { ControlledByCheck } from "./controller.js";
import type { FetchPort } from "./fetch-port.js";
import type { ProofVerifyOptions, SuiteRegistry } from "./proof.js";
import type { DataIntegrityProof, VerificationError } from "./types.js";
/** The controller-check selection inputs shared by both verify entry points. */
export interface ControllerSelection {
    readonly isControlledBy?: ControlledByCheck;
    readonly fetch?: FetchPort;
}
/** Select the controller check: explicit override → document-resolved (if fetch) → fail-closed. */
export declare function resolveControlledBy(options: ControllerSelection, expectedPurpose: string): ControlledByCheck;
/** Strip a bare `proofPurpose` token to compare regardless of IRI vs short form. */
export declare function normalizePurpose(purpose: string): string;
/**
 * The validity-window gate (VC-DM 2.0 §"Validity Period"): `now ≥ validFrom` and,
 * when present, `now ≤ validUntil`. An unparseable date is ignored (not fatal) —
 * matching the structured verifier's long-standing behaviour. Pure over plain data.
 */
export declare function checkValidityWindow(now: Date, validFrom: string | undefined, validUntil: string | undefined): VerificationError[];
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
export declare function verifyProofSet(input: ProofSetInput): Promise<VerificationError[]>;
//# sourceMappingURL=verify-core.d.ts.map