import type { FetchPort } from "./fetch-port.js";
/** A JSON value (for arbitrary `credentialSubject` claims that round-trip as RDF). */
export type JsonValue = string | number | boolean | null | {
    readonly [key: string]: JsonValue;
} | readonly JsonValue[];
/**
 * A structured W3C Verifiable Credential 2.0 (the UNSIGNED claim graph — the
 * `proof` is added by {@link issue} / a {@link ProofSuite}). Fields mirror VCDM
 * 2.0; `validFrom`/`validUntil` are the 2.0 names (not 1.1's
 * `issuanceDate`/`expirationDate`).
 */
export interface Credential {
    /** The credential IRI (`@id`). Defaults to a random `urn:uuid:` if omitted. */
    readonly id?: string;
    /**
     * Credential type(s) beyond `VerifiableCredential` (always implied). E.g.
     * `["AgentAuthorizationCredential"]`. Plain type names map through the inline
     * context; absolute IRIs are kept verbatim.
     */
    readonly type?: readonly string[];
    /** The issuing party — a WebID or DID IRI (required). */
    readonly issuer: string;
    /** Issuance / validity start, ISO-8601 dateTime. Defaults to now at issue time. */
    readonly validFrom?: string;
    /** Expiry, ISO-8601 dateTime. Absent = no expiry. */
    readonly validUntil?: string;
    /** The credential subject(s) — the claims being asserted. */
    readonly credentialSubject: CredentialSubject | readonly CredentialSubject[];
    /**
     * The credential's revocation/suspension status entry (or entries) — a W3C
     * Bitstring Status List v1.0 `BitstringStatusListEntry`. Lowered UNDER the proof
     * (so an attacker cannot strip or swap it), and checked by {@link verifyCredential}'s
     * status gate. Absent = no status list (no revocation information).
     */
    readonly credentialStatus?: CredentialStatus | readonly CredentialStatus[];
}
/**
 * A W3C Bitstring Status List v1.0 `credentialStatus` entry: a pointer into a
 * published, GZIP-compressed bitstring at `statusListCredential`, bit `statusListIndex`,
 * for the given `statusPurpose` (`"revocation"` — permanent; `"suspension"` — reversible).
 */
export interface CredentialStatus {
    /** The status entry IRI (`@id`). Optional. */
    readonly id?: string;
    /** The entry type — MUST be `"BitstringStatusListEntry"`. */
    readonly type: string;
    /** `"revocation"` (permanent) or `"suspension"` (reversible while set). */
    readonly statusPurpose: string;
    /** This credential's bit position within the referenced bitstring. */
    readonly statusListIndex: string | number;
    /** The IRI of the `BitstringStatusListCredential` to dereference and check. */
    readonly statusListCredential: string;
}
/** A credential subject: an optional `id` (the subject IRI) plus arbitrary claims. */
export interface CredentialSubject {
    /** The subject IRI (`@id`). Optional — a bearer/anonymous subject has none. */
    readonly id?: string;
    /** Arbitrary RDF-mappable claims about the subject. */
    readonly [claim: string]: JsonValue | undefined;
}
/**
 * The structured agent-authorization claim — the headline M4 use case lowered to
 * a {@link Credential} of type `AgentAuthorizationCredential` by
 * {@link buildAgentAuthorizationCredential}: "principal `issuer` authorizes agent
 * `authorizes` to `action` over `target` under ODRL `policy`".
 */
export interface AgentAuthorization {
    /** The principal granting the authorization — a WebID (becomes the VC issuer). */
    readonly principal: string;
    /** The authorized agent — a WebID or `@jeswr/solid-agent-card` agent IRI. */
    readonly agent: string;
    /** The authorized action IRI(s) — an `acl:` mode or an ODRL action IRI. */
    readonly action: string | readonly string[];
    /** The resource / asset the authorization governs (optional). */
    readonly target?: string;
    /** Link to the governing `@jeswr/solid-odrl` ODRL policy graph (optional). */
    readonly policy?: string;
    /** Credential IRI (optional — random `urn:uuid:` if omitted). */
    readonly id?: string;
    /** Validity start (optional — now at issue time). */
    readonly validFrom?: string;
    /** Expiry (optional). */
    readonly validUntil?: string;
}
/**
 * An embedded W3C Data Integrity proof (one `proof` node on a signed credential /
 * presentation). The `proofValue` is multibase-`z` (base58btc) encoded signature
 * octets, per Data Integrity.
 */
export interface DataIntegrityProof {
    /** Always `"DataIntegrityProof"`. */
    readonly type: "DataIntegrityProof";
    /** The named cryptosuite (e.g. `eddsa-rdfc-2022`, `ecdsa-rdfc-2019`). */
    readonly cryptosuite: string;
    /** The verification method IRI — the key id the proof is checked against. */
    readonly verificationMethod: string;
    /** Why the proof was created (default `assertionMethod`). */
    readonly proofPurpose: string;
    /** When the proof was created (ISO-8601 dateTime). */
    readonly created?: string;
    /** The multibase-encoded signature octets. */
    readonly proofValue: string;
}
/** A verifiable (signed) credential = a {@link Credential} with one or more proofs. */
export interface VerifiableCredential extends Credential {
    /** One proof, or an array of proofs (a credential may carry several). */
    readonly proof: DataIntegrityProof | readonly DataIntegrityProof[];
}
/** A W3C Verifiable Presentation 2.0 (the unsigned form). */
export interface Presentation {
    /** The presentation IRI (`@id`). Optional. */
    readonly id?: string;
    /** Presentation type(s) beyond `VerifiablePresentation`. */
    readonly type?: readonly string[];
    /** The presenting party — a WebID/DID (optional for a holder-less presentation). */
    readonly holder?: string;
    /** The credentials being presented. */
    readonly verifiableCredential: readonly VerifiableCredential[];
}
/** A verifiable (signed) presentation = a {@link Presentation} with proof(s). */
export interface VerifiablePresentation extends Presentation {
    readonly proof: DataIntegrityProof | readonly DataIntegrityProof[];
}
/**
 * A verification key pair (a `verificationMethod` IRI bound to a key). The key
 * material is a WebCrypto `CryptoKey` — the only key type the concrete suite signs
 * with (jose-generated / JWK-imported). A pluggable suite may use a different key
 * model; this is the shape the bundled Data Integrity suites expect.
 */
export interface KeyPair {
    /** The verification method IRI (becomes `proof.verificationMethod`). */
    readonly verificationMethod: string;
    /** The private signing key (WebCrypto). */
    readonly privateKey: CryptoKey;
    /** The public verification key (WebCrypto). */
    readonly publicKey: CryptoKey;
}
/**
 * The result of a verification. `verified` is the single source of truth; on
 * failure `errors` lists every distinct reason (signature, expiry,
 * issuer-binding, structural) so a caller can act on the specific failure — a
 * security surface must never collapse all failures into a generic "false".
 */
export interface VerificationResult {
    /** `true` IFF every proof verified AND every validity/binding check passed. */
    readonly verified: boolean;
    /** Distinct failure reasons (empty IFF `verified`). */
    readonly errors: readonly VerificationError[];
    /** The verified issuer IRI (when a single issuer was bound), for convenience. */
    readonly issuer?: string;
}
/** A structured, machine-actionable verification failure. */
export interface VerificationError {
    /** The failure category (so a caller can branch on it). */
    readonly code: VerificationErrorCode;
    /** A human-readable explanation. */
    readonly message: string;
}
/** The closed set of verification failure categories. */
export type VerificationErrorCode = "MALFORMED" | "NO_PROOF" | "UNKNOWN_CRYPTOSUITE" | "INVALID_SIGNATURE" | "EXPIRED" | "NOT_YET_VALID" | "ISSUER_MISMATCH" | "PROOF_PURPOSE_MISMATCH" | "UNTRUSTED_ISSUER" | "REVOKED" | "SUSPENDED" | "STATUS_RETRIEVAL_ERROR";
/** Options shared by the verification entrypoints. */
export interface VerifyOptions {
    /** The instant to evaluate validity against (default `new Date()`). Injectable for tests. */
    readonly now?: Date;
    /**
     * If set, the issuer IRI MUST be in this allowlist or verification fails with
     * `UNTRUSTED_ISSUER` — the trusted-issuer model PSS's verifier also uses. When
     * omitted, issuer trust is the caller's concern (signature is still checked).
     */
    readonly trustedIssuers?: readonly string[];
    /** The expected `proofPurpose` (default `assertionMethod`). */
    readonly expectedProofPurpose?: string;
    /**
     * The injected SSRF-guarded network port for the gates that must dereference a
     * remote resource — the document-resolved issuer–key controller check, the
     * Bitstring Status List v1.0 status gate, and the by-reference policy digest
     * check. Inject `@jeswr/guarded-fetch/node`'s `nodeGuardedFetch` (see
     * `@jeswr/solid-vc/node`). When ABSENT, those gates FAIL CLOSED (deny) rather than
     * silently skipping — a skipped revocation/controller check is an accept.
     */
    readonly fetch?: FetchPort;
    /**
     * Whether to run the Bitstring Status List v1.0 status gate when the credential
     * carries a `credentialStatus` (default `true`). Set `false` only to isolate other
     * gates in a test — a production verify MUST keep it on (a skipped revocation check
     * is an accept). Internally forced `false` when verifying a status-list credential
     * (to avoid recursion).
     */
    readonly checkStatus?: boolean;
    /**
     * A monotonic revocation memory for the `"revocation"` purpose (this note's D7):
     * once a credential has been observed revoked, a later CLEAR bit MUST NOT un-revoke
     * it (closing the "attacker briefly flips the bit back during a cache window" replay).
     * Injectable + persistable; omit to disable monotonic memory (each check is fresh).
     * `"suspension"` is the reversible purpose and never consults this store.
     */
    readonly revocationStore?: RevocationStore;
}
/**
 * A tiny persisted set for revocation MONOTONICITY: it remembers the keys of
 * credentials observed revoked so a later clear read cannot un-revoke them. Keys are
 * opaque (`<credentialId>|revocation`). Both methods may be sync or async.
 */
export interface RevocationStore {
    /** Whether `key` was previously recorded revoked. */
    has(key: string): boolean | Promise<boolean>;
    /** Record `key` as revoked (idempotent). */
    add(key: string): void | Promise<void>;
}
/** Options for issuing/signing. */
export interface IssueOptions {
    /** Override the proof's `created` timestamp (default now). Injectable for tests. */
    readonly created?: Date;
    /** The `proofPurpose` (default `assertionMethod`). */
    readonly proofPurpose?: string;
}
//# sourceMappingURL=types.d.ts.map