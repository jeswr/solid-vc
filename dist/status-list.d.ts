import type { ControlledByCheck } from "./controller.js";
import type { FetchPort } from "./fetch-port.js";
import type { ProofVerifyOptions, SuiteRegistry } from "./proof.js";
import type { CredentialStatus, RevocationStore, VerificationError } from "./types.js";
import type { ParsedVerification } from "./verify-rdf.js";
/**
 * The injected "verify a fetched serialized VC over its exact RDF" function —
 * `parseAndVerifyCredential` (src/verify-rdf.ts), passed IN rather than imported so
 * this module stays a leaf (no runtime import cycle: verify-rdf value-imports
 * {@link checkCredentialStatus}).
 */
export type StatusCredentialVerifier = (body: string, contentType: string, options: {
    readonly resolveKey: ProofVerifyOptions["resolveKey"];
    readonly registry: SuiteRegistry;
    readonly now: Date;
    readonly baseIRI: string;
    readonly fetch?: FetchPort;
    readonly isControlledBy?: ControlledByCheck;
    readonly checkStatus: false;
}) => Promise<ParsedVerification>;
/** Inputs to {@link checkCredentialStatus}. */
export interface StatusCheckParams {
    /** Verify the fetched status-list credential over its exact RDF (inject `parseAndVerifyCredential`). */
    readonly verifyStatusCredential: StatusCredentialVerifier;
    /** The credential's `credentialStatus` entries (already normalised to an array). */
    readonly entries: readonly CredentialStatus[];
    /** The hop credential's IRI — the monotonic-store key + never-revoked tracking. */
    readonly credentialId: string | undefined;
    /** The hop credential's issuer — the status-list credential MUST share it. */
    readonly issuer: string;
    /** The single evaluation instant (shared with the caller's other gates). */
    readonly now: Date;
    /** The SSRF-guarded fetch; ABSENT → every status entry fails closed (deny). */
    readonly fetch?: FetchPort;
    /** Optional monotonic revocation memory (this note's D7). */
    readonly revocationStore?: RevocationStore;
    /** The accepted proof suites (for verifying the status-list credential). */
    readonly registry: SuiteRegistry;
    /** Resolve a verification method to a public key (for the status-list credential). */
    readonly resolveKey: ProofVerifyOptions["resolveKey"];
    /** The controller check override, threaded to the status-list credential's verify. */
    readonly isControlledBy?: ControlledByCheck;
}
/**
 * Run the Bitstring Status List gate over every `credentialStatus` entry. Returns the
 * accumulated errors (empty IFF no entry is revoked/suspended and every list resolved).
 */
export declare function checkCredentialStatus(params: StatusCheckParams): Promise<VerificationError[]>;
//# sourceMappingURL=status-list.d.ts.map