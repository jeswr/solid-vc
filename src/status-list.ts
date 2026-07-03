// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The Bitstring Status List v1.0 (W3C Recommendation) status gate — the FAIL-CLOSED
// revocation / suspension check for verifyCredential (gate 9). Implements this note's
// §"Revocation" verification-side mapping and Bitstring Status List §"Validate
// Algorithm":
//
//   - Retrieve the referenced BitstringStatusListCredential through the injected
//     SSRF-guarded fetch; a retrieval failure, a status-list credential that fails
//     verification, an issuer that differs from the hop issuer, a statusPurpose that
//     does not match the entry, a bitstring shorter than the 131,072-entry minimum,
//     or an out-of-range index → the hop is UNVERIFIABLE → deny (STATUS_RETRIEVAL_ERROR).
//   - A set `"revocation"` bit → REVOKED (permanent); a set `"suspension"` bit →
//     SUSPENDED (reversible while set) — the two are mapped but kept DISTINCT.
//   - Monotonicity (this note's D7): once observed revoked, a later CLEAR read does
//     NOT un-revoke (via the injectable {@link RevocationStore}); suspension is the
//     reversible purpose and never consults the store.
//
// Everything that cannot be established resolves to deny — a skipped revocation check
// is an accept, which for an authorization credential is strictly worse than a
// status-outage denial.

import { gunzipSync } from "node:zlib";
import type { DatasetCore } from "@rdfjs/types";
import { base64url } from "multiformats/bases/base64";
import type { ControlledByCheck } from "./controller.js";
import type { FetchPort } from "./fetch-port.js";
import type { ProofVerifyOptions, SuiteRegistry } from "./proof.js";
import type { CredentialStatus, RevocationStore, VerificationError } from "./types.js";
import type { ParsedVerification } from "./verify-rdf.js";
import { STATUS_ENCODED_LIST, STATUS_PURPOSE } from "./vocab.js";

/** The minimum uncompressed bitstring size (Bitstring Status List §"Bitstring", herd privacy). */
const MIN_BITSTRING_ENTRIES = 131072;

/**
 * The injected "verify a fetched serialized VC over its exact RDF" function —
 * `parseAndVerifyCredential` (src/verify-rdf.ts), passed IN rather than imported so
 * this module stays a leaf (no runtime import cycle: verify-rdf value-imports
 * {@link checkCredentialStatus}).
 */
export type StatusCredentialVerifier = (
  body: string,
  contentType: string,
  options: {
    readonly resolveKey: ProofVerifyOptions["resolveKey"];
    readonly registry: SuiteRegistry;
    readonly now: Date;
    readonly baseIRI: string;
    readonly fetch?: FetchPort;
    readonly isControlledBy?: ControlledByCheck;
    readonly checkStatus: false;
  },
) => Promise<ParsedVerification>;

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
export async function checkCredentialStatus(
  params: StatusCheckParams,
): Promise<VerificationError[]> {
  const errors: VerificationError[] = [];
  for (const entry of params.entries) {
    errors.push(...(await checkOneEntry(entry, params)));
  }
  return errors;
}

/** The monotonic-store key for a credential + purpose (revocation only). */
function monotonicKey(credentialId: string): string {
  return `${credentialId}|revocation`;
}

async function checkOneEntry(
  entry: CredentialStatus,
  params: StatusCheckParams,
): Promise<VerificationError[]> {
  if (entry.type !== "BitstringStatusListEntry") {
    return [retrievalError(`unsupported credentialStatus type "${entry.type}"`)];
  }
  const purpose = entry.statusPurpose;
  if (purpose !== "revocation" && purpose !== "suspension") {
    return [retrievalError(`unsupported statusPurpose "${purpose}"`)];
  }
  const index = Number(entry.statusListIndex);
  if (!Number.isSafeInteger(index) || index < 0) {
    return [retrievalError(`invalid statusListIndex "${entry.statusListIndex}"`)];
  }

  // Monotonicity: a previously-observed revocation is permanent (never un-revoked by
  // a later clear read). Short-circuits before any network I/O.
  const monoKey =
    purpose === "revocation" && params.credentialId !== undefined
      ? monotonicKey(params.credentialId)
      : undefined;
  if (monoKey !== undefined && params.revocationStore !== undefined) {
    if (await params.revocationStore.has(monoKey)) {
      return [
        { code: "REVOKED", message: `credential ${params.credentialId} was previously revoked` },
      ];
    }
  }

  if (params.fetch === undefined) {
    return [retrievalError("no fetch injected — cannot retrieve the status list (fail-closed)")];
  }

  const list = await fetchStatusList(entry, purpose, params, params.fetch);
  if ("error" in list) return [list.error];

  const bitSet = bitAt(list.bytes, index);
  if (bitSet === undefined) {
    return [retrievalError(`statusListIndex ${index} is out of range for the bitstring`)];
  }
  if (!bitSet) return [];

  if (purpose === "revocation") {
    if (monoKey !== undefined && params.revocationStore !== undefined) {
      await params.revocationStore.add(monoKey);
    }
    return [{ code: "REVOKED", message: `credential is revoked (statusListIndex ${index})` }];
  }
  return [{ code: "SUSPENDED", message: `credential is suspended (statusListIndex ${index})` }];
}

/** Fetch + verify + decode the status-list credential, or a fail-closed error. */
async function fetchStatusList(
  entry: CredentialStatus,
  purpose: string,
  params: StatusCheckParams,
  fetch: FetchPort,
): Promise<{ bytes: Uint8Array } | { error: VerificationError }> {
  let body: string;
  let contentType: string;
  try {
    const response = await fetch(entry.statusListCredential);
    if (!response.ok) {
      return { error: retrievalError(`status list HTTP ${response.status}`) };
    }
    body = await response.text();
    contentType = response.headers.get("content-type") ?? "text/turtle";
  } catch {
    return { error: retrievalError("status list retrieval threw") };
  }

  // The status-list credential is itself a VC — verify it over its EXACT bytes and
  // require the SAME issuer as the hop (the delegator revokes what it issued).
  const result = await params.verifyStatusCredential(body, contentType, {
    resolveKey: params.resolveKey,
    registry: params.registry,
    now: params.now,
    baseIRI: entry.statusListCredential,
    ...(params.fetch !== undefined ? { fetch: params.fetch } : {}),
    ...(params.isControlledBy !== undefined ? { isControlledBy: params.isControlledBy } : {}),
    // Never recurse into the status-list credential's OWN status (avoids a cycle).
    checkStatus: false,
  });
  if (!result.verified) {
    return { error: retrievalError("status list credential failed verification") };
  }
  if (result.issuer !== params.issuer) {
    return {
      error: retrievalError(`status list issuer ${result.issuer} != hop issuer ${params.issuer}`),
    };
  }

  const dataset = result.dataset;
  if (dataset === undefined) {
    return { error: retrievalError("status list credential parsed to no dataset") };
  }
  const listPurpose = firstObjectLiteral(dataset, STATUS_PURPOSE);
  if (listPurpose !== purpose) {
    return {
      error: retrievalError(`status list purpose "${listPurpose}" != entry "${purpose}"`),
    };
  }
  const encoded = firstObjectLiteral(dataset, STATUS_ENCODED_LIST);
  if (encoded === undefined) {
    return { error: retrievalError("status list has no encodedList") };
  }

  let bytes: Uint8Array;
  try {
    bytes = decodeBitstring(encoded);
  } catch {
    return { error: retrievalError("status list encodedList failed to decode") };
  }
  if (bytes.length * 8 < MIN_BITSTRING_ENTRIES) {
    return { error: retrievalError("status list bitstring is shorter than the minimum size") };
  }
  return { bytes };
}

/** Decode a multibase-base64url, GZIP-compressed `encodedList` to raw bitstring bytes. */
function decodeBitstring(encodedList: string): Uint8Array {
  // Bitstring Status List §"Bitstring Encoding": multibase base64url (prefix `u`),
  // then GZIP. `multiformats` validates the multibase prefix; `node:zlib` gunzips.
  const compressed = base64url.decode(encodedList);
  return new Uint8Array(gunzipSync(compressed));
}

/**
 * The bit at `index`, MSB-first within each byte (Bitstring Status List §"Bitstring":
 * "the least index is the leftmost/most-significant bit of the first byte"). Returns
 * `undefined` when `index` is beyond the bitstring.
 */
function bitAt(bytes: Uint8Array, index: number): boolean | undefined {
  // Guard the full 64-bit-safe integer range explicitly: `>>> 3` would coerce a large
  // index to 32 bits and read the WRONG bit instead of failing closed as out of range.
  if (!Number.isSafeInteger(index) || index < 0 || index >= bytes.length * 8) {
    return undefined;
  }
  const byteIndex = Math.floor(index / 8);
  const bitInByte = index % 8;
  const byte = bytes[byteIndex] as number;
  return ((byte >> (7 - bitInByte)) & 1) === 1;
}

/** The first literal object of a predicate anywhere in the dataset, or `undefined`. */
function firstObjectLiteral(dataset: DatasetCore, predicate: string): string | undefined {
  for (const quad of dataset.match()) {
    if (quad.predicate.value === predicate && quad.object.termType === "Literal") {
      return quad.object.value;
    }
  }
  return undefined;
}

/** Build a STATUS_RETRIEVAL_ERROR with a message. */
function retrievalError(message: string): VerificationError {
  return { code: "STATUS_RETRIEVAL_ERROR", message };
}
