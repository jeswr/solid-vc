// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Policy-CONTENT binding (this note's §"Binding the policy content, not just its
// IRI"; DECISIONS.md D4). The `svc:policy` an agent-authorization credential carries
// MUST be bound by CONTENT, in exactly one of two ways:
//
//   - EMBEDDED (RECOMMENDED): the policy is an inline object in the claim graph, so
//     the Data Integrity proof already signs every policy triple. Accepted as-is.
//   - BY REFERENCE WITH DIGEST: `svc:policy` is an IRI AND the credential carries a
//     VCDM 2.0 `relatedResource` entry for that IRI with a `digestSRI` / `digestMultibase`.
//     We dereference the IRI through the injected SSRF-guarded fetch and verify the
//     retrieved OCTETS against the signed digest — fail-closed on mismatch/retrieval.
//
// A BARE, digest-less `svc:policy <iri>` reference — the form the builder emitted
// before this change — is an integrity hole (the document is free to be swapped after
// signing) and is REJECTED with POLICY_INTEGRITY.
//
// The digest primitive delegates to `node:crypto` (SRI) and `multiformats` (multibase
// multihash) — never a hand-rolled hash; the POLICY of which forms are acceptable is
// the small reviewed code here.

import { createHash, timingSafeEqual } from "node:crypto";
import { base16 } from "multiformats/bases/base16";
import { base58btc } from "multiformats/bases/base58";
import { base64, base64url } from "multiformats/bases/base64";
import * as Digest from "multiformats/hashes/digest";
import type { FetchPort } from "./fetch-port.js";
import type {
  CredentialSubject,
  JsonValue,
  RelatedResource,
  VerifiableCredential,
  VerificationError,
} from "./types.js";
import { SVC_POLICY } from "./vocab.js";

/** The verified binding of a credential's `svc:policy`. */
export type BoundPolicy =
  | { readonly form: "embedded"; readonly content: JsonValue }
  | {
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

/** Multihash codes → the `node:crypto` hash name we verify a `digestMultibase` with. */
const MULTIHASH_ALG: Record<number, string> = { 18: "sha256", 19: "sha512", 32: "sha384" };
/** The `digestSRI` algorithm tokens we accept. */
const SRI_ALG: Record<string, string> = { sha256: "sha256", sha384: "sha384", sha512: "sha512" };

/** A multibase decoder covering the prefixes an issuer might use (`z`/`u`/`m`/`f`). */
const MULTIBASE = base58btc.decoder.or(base64.decoder).or(base64url.decoder).or(base16.decoder);

/**
 * Resolve + verify the CONTENT binding of `vc`'s `svc:policy`. Assumes the
 * credential's own proof has ALREADY been verified (so the embedded content / the
 * `relatedResource` digest are trusted-signed); this checks the binding FORM and, for
 * a reference, that the fetched octets match the signed digest. A credential with no
 * `svc:policy` yields `{ policy: undefined, errors: [] }` (nothing to bind).
 */
export async function resolveBoundPolicy(
  vc: VerifiableCredential,
  options: { readonly fetch?: FetchPort },
): Promise<PolicyBindingResult> {
  const subject = subjectWithPolicy(vc);
  const policyValue = subject?.[SVC_POLICY];
  if (policyValue === undefined) return { errors: [] };

  // EMBEDDED: an inline object is signed as part of the claim graph.
  if (typeof policyValue === "object" && policyValue !== null) {
    return { policy: { form: "embedded", content: policyValue }, errors: [] };
  }
  if (typeof policyValue !== "string") {
    return { errors: [integrityError("svc:policy is neither an IRI nor an embedded object")] };
  }

  // BY REFERENCE: require a relatedResource digest for this exact IRI.
  const related = relatedResourceFor(vc, policyValue);
  if (
    related === undefined ||
    (related.digestSRI === undefined && related.digestMultibase === undefined)
  ) {
    return {
      errors: [
        integrityError(`bare policy reference <${policyValue}> has no relatedResource digest (D4)`),
      ],
    };
  }
  if (options.fetch === undefined) {
    return {
      errors: [integrityError("no fetch injected — cannot dereference the policy (fail-closed)")],
    };
  }

  let octets: Uint8Array;
  let mediaType: string | undefined;
  try {
    const response = await options.fetch(policyValue);
    if (!response.ok) {
      return { errors: [integrityError(`policy HTTP ${response.status}`)] };
    }
    octets = new Uint8Array(await response.arrayBuffer());
    mediaType = related.mediaType ?? response.headers.get("content-type") ?? undefined;
  } catch {
    return { errors: [integrityError("policy retrieval threw")] };
  }

  if (!digestMatches(octets, related)) {
    return {
      errors: [integrityError(`policy octets do not match the signed digest for <${policyValue}>`)],
    };
  }
  return {
    policy: {
      form: "reference",
      iri: policyValue,
      octets,
      ...(mediaType !== undefined ? { mediaType } : {}),
    },
    errors: [],
  };
}

/** The single credential subject carrying an `svc:policy`, or `undefined`. */
function subjectWithPolicy(vc: VerifiableCredential): CredentialSubject | undefined {
  const subjects = Array.isArray(vc.credentialSubject)
    ? vc.credentialSubject
    : [vc.credentialSubject];
  return subjects.find((s) => s[SVC_POLICY] !== undefined);
}

/** The `relatedResource` entry whose `id` matches the policy IRI, or `undefined`. */
function relatedResourceFor(vc: VerifiableCredential, iri: string): RelatedResource | undefined {
  if (vc.relatedResource === undefined) return undefined;
  const resources = Array.isArray(vc.relatedResource) ? vc.relatedResource : [vc.relatedResource];
  return resources.find((r) => r.id === iri);
}

/** Whether `octets` match the entry's `digestSRI` and/or `digestMultibase` (all present must hold). */
function digestMatches(octets: Uint8Array, related: RelatedResource): boolean {
  if (related.digestSRI !== undefined && !sriMatches(octets, related.digestSRI)) return false;
  if (related.digestMultibase !== undefined && !multibaseMatches(octets, related.digestMultibase)) {
    return false;
  }
  return true;
}

/** Verify a Subresource-Integrity `<alg>-<base64>` digest over `octets`. */
function sriMatches(octets: Uint8Array, digestSRI: string): boolean {
  const dash = digestSRI.indexOf("-");
  if (dash === -1) return false;
  const alg = SRI_ALG[digestSRI.slice(0, dash)];
  if (alg === undefined) return false;
  let expected: Buffer;
  try {
    expected = Buffer.from(digestSRI.slice(dash + 1), "base64");
  } catch {
    return false;
  }
  const actual = createHash(alg).update(octets).digest();
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Verify a multibase-encoded multihash digest over `octets`. */
function multibaseMatches(octets: Uint8Array, digestMultibase: string): boolean {
  let digest: ReturnType<typeof Digest.decode>;
  try {
    digest = Digest.decode(MULTIBASE.decode(digestMultibase));
  } catch {
    return false;
  }
  const alg = MULTIHASH_ALG[digest.code];
  if (alg === undefined) return false;
  const actual = createHash(alg).update(octets).digest();
  const expected = Buffer.from(digest.digest);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Build a POLICY_INTEGRITY error with a message. */
function integrityError(message: string): VerificationError {
  return { code: "POLICY_INTEGRITY", message };
}
