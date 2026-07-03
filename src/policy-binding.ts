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
import type { Quad } from "@rdfjs/types";
import { base16 } from "multiformats/bases/base16";
import { base58btc } from "multiformats/bases/base58";
import { base64, base64url } from "multiformats/bases/base64";
import * as Digest from "multiformats/hashes/digest";
import type { FetchPort } from "./fetch-port.js";
import type {
  JsonValue,
  RelatedResource,
  VerifiableCredential,
  VerificationError,
} from "./types.js";
import {
  SCHEMA_ENCODING_FORMAT,
  SEC_DIGEST_MULTIBASE,
  SVC_POLICY,
  VC_DIGEST_SRI,
  VC_RELATED_RESOURCE,
} from "./vocab.js";

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
  const policyValues = policyClaimsOf(vc);
  if (policyValues.length === 0) return { errors: [] };
  // One hop per credential (this note's §"Issuance requirements"): several policy
  // claims are ambiguous and must not pass on the strength of one valid one.
  if (policyValues.length > 1) {
    return {
      errors: [integrityError("credential binds multiple policies (one hop per credential)")],
    };
  }
  const policyValue = policyValues[0];

  // EMBEDDED: an inline object is signed as part of the claim graph.
  if (typeof policyValue === "object" && policyValue !== null) {
    return { policy: { form: "embedded", content: policyValue }, errors: [] };
  }
  if (typeof policyValue !== "string") {
    return { errors: [integrityError("svc:policy is neither an IRI nor an embedded object")] };
  }

  // BY REFERENCE: require a relatedResource digest for this exact IRI.
  const related = relatedResourceFor(vc, policyValue);
  return referenceBinding(policyValue, related, options);
}

/** Verify a by-reference policy IRI against its relatedResource digest, or POLICY_INTEGRITY. */
async function referenceBinding(
  iri: string,
  related: RelatedResource | undefined,
  options: { readonly fetch?: FetchPort },
): Promise<PolicyBindingResult> {
  if (
    related === undefined ||
    (related.digestSRI === undefined && related.digestMultibase === undefined)
  ) {
    return {
      errors: [integrityError(`bare policy reference <${iri}> has no relatedResource digest (D4)`)],
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
    const response = await options.fetch(iri);
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
      errors: [integrityError(`policy octets do not match the signed digest for <${iri}>`)],
    };
  }
  return {
    policy: { form: "reference", iri, octets, ...(mediaType !== undefined ? { mediaType } : {}) },
    errors: [],
  };
}

/** Every `svc:policy` claim across the credential's subjects (each subject may carry one). */
function policyClaimsOf(vc: VerifiableCredential): JsonValue[] {
  const subjects = Array.isArray(vc.credentialSubject)
    ? vc.credentialSubject
    : [vc.credentialSubject];
  const out: JsonValue[] = [];
  for (const s of subjects) {
    if (s === null || typeof s !== "object") continue;
    const value = s[SVC_POLICY];
    if (value !== undefined) out.push(value);
  }
  return out;
}

/** The `relatedResource` entry whose `id` matches the policy IRI (malformed entries skipped). */
function relatedResourceFor(vc: VerifiableCredential, iri: string): RelatedResource | undefined {
  if (vc.relatedResource === undefined) return undefined;
  const resources = Array.isArray(vc.relatedResource) ? vc.relatedResource : [vc.relatedResource];
  // Runtime-validate each entry: an untrusted VC may carry `relatedResource: [null]` or
  // a non-object, which must fail closed (skip), never throw on `r.id` access.
  return resources.find(
    (r): r is RelatedResource =>
      r !== null && typeof r === "object" && (r as { id?: unknown }).id === iri,
  );
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

/** The predicates that carry a relatedResource DIGEST (not a policy description). */
const DIGEST_PREDICATES = new Set<string>([
  VC_DIGEST_SRI,
  SEC_DIGEST_MULTIBASE,
  SCHEMA_ENCODING_FORMAT,
]);

/**
 * Enforce policy-content binding over the SIGNED quads of a parsed VC (the RDF-graph
 * counterpart of {@link resolveBoundPolicy}, for {@link parseAndVerifyCredential}).
 * Returns POLICY_INTEGRITY errors (empty when the single `svc:policy` is embedded or a
 * digest-verified reference). Reads ONLY the signed, proof-stripped quads.
 */
export async function policyBindingErrorsFromQuads(
  signedQuads: readonly Quad[],
  options: { readonly fetch?: FetchPort },
): Promise<VerificationError[]> {
  const policyQuads = signedQuads.filter((q) => q.predicate.value === SVC_POLICY);
  if (policyQuads.length === 0) return [];
  if (policyQuads.length > 1) {
    return [integrityError("credential binds multiple policies (one hop per credential)")];
  }
  const object = (policyQuads[0] as Quad).object;
  // An embedded policy is a blank node (always described inline) — accept.
  if (object.termType === "BlankNode") return [];
  if (object.termType !== "NamedNode") {
    return [integrityError("svc:policy object is neither an IRI nor an embedded node")];
  }
  const iri = object.value;

  // A relatedResource digest for this IRI → verify by reference.
  const related = relatedResourceFromQuads(signedQuads, iri);
  if (
    related !== undefined &&
    (related.digestSRI !== undefined || related.digestMultibase !== undefined)
  ) {
    const result = await referenceBinding(iri, related, options);
    return [...result.errors];
  }

  // An IRI described inline (subject of non-digest, non-policy triples) → embedded.
  const describedInline = signedQuads.some(
    (q) =>
      q.subject.value === iri &&
      q.predicate.value !== SVC_POLICY &&
      !DIGEST_PREDICATES.has(q.predicate.value),
  );
  if (describedInline) return [];

  // Otherwise: a bare, digest-less, undescribed reference.
  return [integrityError(`bare policy reference <${iri}> has no relatedResource digest (D4)`)];
}

/** Read the relatedResource digest entry for `iri` from the signed quads, if present. */
function relatedResourceFromQuads(
  signedQuads: readonly Quad[],
  iri: string,
): RelatedResource | undefined {
  const linked = signedQuads.some(
    (q) => q.predicate.value === VC_RELATED_RESOURCE && q.object.value === iri,
  );
  if (!linked) return undefined;
  let digestSRI: string | undefined;
  let digestMultibase: string | undefined;
  let mediaType: string | undefined;
  for (const q of signedQuads) {
    if (q.subject.value !== iri || q.object.termType !== "Literal") continue;
    if (q.predicate.value === VC_DIGEST_SRI) digestSRI = q.object.value;
    else if (q.predicate.value === SEC_DIGEST_MULTIBASE) digestMultibase = q.object.value;
    else if (q.predicate.value === SCHEMA_ENCODING_FORMAT) mediaType = q.object.value;
  }
  return {
    id: iri,
    ...(digestSRI !== undefined ? { digestSRI } : {}),
    ...(digestMultibase !== undefined ? { digestMultibase } : {}),
    ...(mediaType !== undefined ? { mediaType } : {}),
  };
}
