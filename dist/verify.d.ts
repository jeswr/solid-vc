import { type ControlledByCheck } from "./controller.js";
import type { ProofVerifyOptions, SuiteRegistry } from "./proof.js";
import type { VerifiableCredential, VerificationResult, VerifyOptions } from "./types.js";
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
     *     issuer's own authoritative document and confirms it lists the method under
     *     `sec:assertionMethod` / `sec:controller`;
     *   - if NO `fetch` is provided → FAIL CLOSED (deny). The unsafe string-prefix
     *     heuristic is NO LONGER the default; import `prefixControlledBy` to opt into
     *     it explicitly (documented unsafe).
     */
    readonly isControlledBy?: ControlledByCheck;
}
/**
 * Verify a {@link VerifiableCredential}. Returns a {@link VerificationResult}
 * whose `verified` is `true` IFF every gate passed; on failure `errors` lists
 * every distinct reason. Never throws on an invalid credential.
 */
export declare function verifyCredential(vc: VerifiableCredential, options: VerifyCredentialOptions): Promise<VerificationResult>;
//# sourceMappingURL=verify.d.ts.map