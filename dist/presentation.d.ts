import type { Quad } from "@rdfjs/types";
import { type ProofSuite } from "./proof.js";
import type { IssueOptions, KeyPair, Presentation, VerifiablePresentation, VerificationError, VerificationResult } from "./types.js";
import type { VerifyCredentialOptions } from "./verify.js";
/**
 * Lower a {@link Presentation} (UNSIGNED — no proof) to RDF quads: the presentation
 * node (`VerifiablePresentation`), its `holder`, and — per presented credential — a
 * `verifiableCredential` link PLUS a `sec:digestMultibase` of the credential's SIGNED
 * canonical form. Binding the digest (not merely the credential `id`) is what stops a
 * same-`id` credential from being SUBSTITUTED without breaking the presentation
 * signature. Async because the digest canonicalizes each credential. The presentation
 * proof is computed over these quads.
 */
export declare function presentationToRdf(presentation: Presentation): Promise<Quad[]>;
/** Options for {@link signPresentation}. */
export interface SignPresentationOptions extends IssueOptions {
    /** The anti-replay challenge to bind (Data Integrity §"challenge"). */
    readonly challenge?: string;
    /** The intended relying-party domain to bind (Data Integrity §"domain"). */
    readonly domain?: string;
    /** The proof suite (default the bundled `eddsa-rdfc-2022`). */
    readonly suite?: ProofSuite;
}
/**
 * Sign (issue) a Verifiable Presentation: the holder signs over the presentation graph
 * with `proofPurpose = authentication`, binding `challenge` + `domain`. The embedded
 * credentials keep their OWN proofs; this proof authenticates the PRESENTER.
 */
export declare function signPresentation(presentation: Presentation, key: KeyPair | unknown, options?: SignPresentationOptions): Promise<VerifiablePresentation>;
/** Options for {@link verifyPresentation}: the credential options + expected challenge/domain. */
export interface VerifyPresentationOptions extends VerifyCredentialOptions {
    /** The challenge the verifier issued; the presentation proof MUST bind exactly it. */
    readonly challenge?: string;
    /** The verifier's domain; the presentation proof MUST bind exactly it. */
    readonly domain?: string;
}
/** The result of {@link verifyPresentation}. */
export interface PresentationVerificationResult {
    /** `true` IFF every embedded credential verified, the holder proved control, and challenge/domain matched. */
    readonly verified: boolean;
    /** Distinct failure reasons. */
    readonly errors: readonly VerificationError[];
    /** The authenticated presenter (when the presentation proof verified). */
    readonly holder?: string;
    /** Per-credential verification results, in order. */
    readonly credentialResults: readonly VerificationResult[];
}
/**
 * Verify a {@link VerifiablePresentation}: every embedded credential, the presentation
 * proof (authentication purpose, holder-controlled key, challenge + domain), and holder
 * binding. Never throws; fail-closed.
 */
export declare function verifyPresentation(vp: VerifiablePresentation, options: VerifyPresentationOptions): Promise<PresentationVerificationResult>;
//# sourceMappingURL=presentation.d.ts.map