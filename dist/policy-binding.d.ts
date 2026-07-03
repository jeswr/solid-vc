import type { Quad } from "@rdfjs/types";
import type { FetchPort } from "./fetch-port.js";
import type { JsonValue, VerifiableCredential, VerificationError } from "./types.js";
/** The verified binding of a credential's `svc:policy`. */
export type BoundPolicy = {
    readonly form: "embedded";
    readonly content: JsonValue;
} | {
    readonly form: "reference";
    readonly iri: string;
    readonly octets: Uint8Array;
    readonly mediaType?: string;
};
/** The outcome of {@link resolveBoundPolicy}: the bound policy, or the errors. */
export interface PolicyBindingResult {
    /** The content-bound policy (embedded content, or digest-verified fetched octets). */
    readonly policy?: BoundPolicy;
    /** POLICY_INTEGRITY errors (bare reference, missing digest, digest mismatch, …). */
    readonly errors: readonly VerificationError[];
}
/**
 * Resolve + verify the CONTENT binding of `vc`'s `svc:policy`. Assumes the
 * credential's own proof has ALREADY been verified (so the embedded content / the
 * `relatedResource` digest are trusted-signed); this checks the binding FORM and, for
 * a reference, that the fetched octets match the signed digest. A credential with no
 * `svc:policy` yields `{ policy: undefined, errors: [] }` (nothing to bind).
 */
export declare function resolveBoundPolicy(vc: VerifiableCredential, options: {
    readonly fetch?: FetchPort;
}): Promise<PolicyBindingResult>;
/**
 * Enforce policy-content binding over the SIGNED quads of a parsed VC (the RDF-graph
 * counterpart of {@link resolveBoundPolicy}, for {@link parseAndVerifyCredential}).
 * Returns POLICY_INTEGRITY errors (empty when the single `svc:policy` is embedded or a
 * digest-verified reference). Reads ONLY the signed, proof-stripped quads.
 */
export declare function policyBindingErrorsFromQuads(signedQuads: readonly Quad[], options: {
    readonly fetch?: FetchPort;
}): Promise<VerificationError[]>;
//# sourceMappingURL=policy-binding.d.ts.map