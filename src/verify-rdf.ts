// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Verify a FETCHED, serialized Verifiable Credential over its EXACT RDF graph —
// the counterpart to {@link verifyCredential}, which verifies a structured object it
// re-lowers. A status-list credential (src/status-list.ts), an embedded/referenced
// policy, and the future composed chain verifier all arrive as bytes from an
// untrusted origin; they MUST be verified over the graph parsed from THOSE bytes
// (Data Integrity computes the signature over the canonical claim graph), never over
// a re-serialization, or the digest/signature would bind to the wrong representation.
//
// The signature-covered document quads are reconstructed by removing the proof node(s)
// from the parsed dataset (Data Integrity §"Verify Proof": the proof is stripped
// before hashing), then the SAME shared gates as verifyCredential run over them
// (src/verify-core.ts) — so the fail-closed proof / validity / controller / purpose
// logic is audited once.

import { parseRdf } from "@jeswr/fetch-rdf";
import type { DatasetCore, Quad } from "@rdfjs/types";
import { policyBindingErrorsFromQuads } from "./policy-binding.js";
import { defaultSuiteRegistry } from "./proof.js";
import { checkCredentialStatus } from "./status-list.js";
import type {
  CredentialStatus,
  DataIntegrityProof,
  VerificationError,
  VerificationResult,
} from "./types.js";
import type { VerifyCredentialOptions } from "./verify.js";
import { checkValidityWindow, resolveControlledBy, verifyProofSet } from "./verify-core.js";
import {
  RDF_TYPE,
  SEC_PROOF,
  STATUS_LIST_CREDENTIAL,
  STATUS_LIST_ENTRY,
  STATUS_LIST_INDEX,
  STATUS_PURPOSE,
  VC_CREDENTIAL_STATUS,
} from "./vocab.js";
import { type CredentialNode, firstIri, firstLiteral, type ProofNode, wrapVc } from "./wrappers.js";

/** The result of {@link parseAndVerifyCredential}: the verdict plus the parsed graph. */
export interface ParsedVerification extends VerificationResult {
  /** The parsed RDF dataset (so a caller can read further claims, e.g. `encodedList`). */
  readonly dataset?: DatasetCore;
  /**
   * The SIGNED claim quads — the dataset with the proof node(s) removed. Read further
   * claims (e.g. a status list's `encodedList`) from HERE, never the full `dataset`:
   * only these quads are covered by the signature, so unsigned triples an attacker
   * appended to the proof graph cannot influence a decision.
   */
  readonly signedDocumentQuads?: readonly Quad[];
  /** The verified credential's IRI (the graph node), when a single credential was found. */
  readonly credentialId?: string;
}

/**
 * Parse a serialized VC (`body` in `contentType` — Turtle / JSON-LD / N-Quads) and
 * verify it over the parsed graph. `options.baseIRI` (default the empty base) resolves
 * relative IRIs; pass the retrieval URL so a document's `<#...>` terms resolve. The
 * gates are identical to {@link verifyCredential}; fail-closed on a parse failure
 * (MALFORMED) and on an ambiguous document (0 or >1 credential nodes).
 */
export async function parseAndVerifyCredential(
  body: string,
  contentType: string,
  options: VerifyCredentialOptions & { readonly baseIRI?: string },
): Promise<ParsedVerification> {
  let dataset: DatasetCore;
  try {
    dataset = (await parseRdf(body, contentType, {
      ...(options.baseIRI !== undefined ? { baseIRI: options.baseIRI } : {}),
    })) as unknown as DatasetCore;
  } catch {
    return {
      verified: false,
      errors: [{ code: "MALFORMED", message: "credential did not parse" }],
    };
  }

  const credentials = wrapVc(dataset).credentials();
  if (credentials.length !== 1) {
    return {
      verified: false,
      errors: [
        {
          code: "MALFORMED",
          message: `expected exactly one credential node, found ${credentials.length}`,
        },
      ],
      dataset,
    };
  }
  const node = credentials[0] as CredentialNode;
  const issuer = firstIri(node.issuers);
  if (issuer === undefined) {
    return {
      verified: false,
      errors: [{ code: "MALFORMED", message: "credential has no issuer IRI" }],
      dataset,
      credentialId: node.value,
    };
  }

  const now = options.now ?? new Date();
  const registry = options.registry ?? defaultSuiteRegistry();
  const expectedPurpose = options.expectedProofPurpose ?? "assertionMethod";
  const controlledBy = resolveControlledBy(options, expectedPurpose);

  const errors: VerificationError[] = [];
  errors.push(
    ...checkValidityWindow(now, firstLiteral(node.validFroms), firstLiteral(node.validUntils)),
  );
  if (options.trustedIssuers !== undefined && !options.trustedIssuers.includes(issuer)) {
    errors.push({ code: "UNTRUSTED_ISSUER", message: `issuer ${issuer} is not trusted` });
  }

  const proofNodes = [...node.proofs];
  if (proofNodes.length === 0) {
    errors.push({ code: "NO_PROOF", message: "credential carries no proof" });
  }
  // A malformed proof node (missing required fields) is a FAILURE, not a silent drop —
  // otherwise a credential whose only proof node is malformed would verify with zero
  // parsed proofs (fail-open).
  const proofs: DataIntegrityProof[] = [];
  for (const proofNode of proofNodes) {
    const parsed = readProof(proofNode);
    if (parsed === undefined) {
      errors.push({
        code: "INVALID_SIGNATURE",
        message: "malformed proof node (missing cryptosuite/method/purpose/proofValue)",
      });
    } else {
      proofs.push(parsed);
    }
  }
  const documentQuads = documentQuadsWithoutProofs(dataset, proofNodes);

  errors.push(
    ...(await verifyProofSet({
      documentQuads,
      proofs,
      issuer,
      registry,
      controlledBy,
      expectedPurpose,
      resolveKey: options.resolveKey,
    })),
  );

  // Status gate (parity with verifyCredential) — a fetched VC must not bypass
  // revocation. Run it ONLY after the core gates passed (errors empty): we must not
  // dereference a status pointer, nor trust the status entry, from a credential whose
  // proof / issuer-binding / validity / trust have not been established. Skipped when
  // explicitly disabled (e.g. verifying a status-list credential itself, to avoid
  // recursion).
  if (errors.length === 0) {
    if (options.checkStatus !== false) {
      const entries = readStatusEntries(dataset, node.value);
      if (entries.length > 0) {
        errors.push(
          ...(await checkCredentialStatus({
            entries,
            credentialId: node.value,
            issuer,
            now,
            fetch: options.fetch,
            revocationStore: options.revocationStore,
            registry,
            resolveKey: options.resolveKey,
            isControlledBy: options.isControlledBy,
            verifyStatusCredential: parseAndVerifyCredential,
          })),
        );
      }
    }
    // Policy-content binding over the SIGNED quads (parity with verifyCredential).
    if (options.checkPolicyBinding !== false) {
      errors.push(...(await policyBindingErrorsFromQuads(documentQuads, { fetch: options.fetch })));
    }
  }

  return errors.length === 0
    ? {
        verified: true,
        errors: [],
        issuer,
        dataset,
        signedDocumentQuads: documentQuads,
        credentialId: node.value,
      }
    : {
        verified: false,
        errors,
        issuer,
        dataset,
        signedDocumentQuads: documentQuads,
        credentialId: node.value,
      };
}

/** Read `credentialStatus` entries for the credential from the parsed RDF graph. */
function readStatusEntries(dataset: DatasetCore, credentialId: string): CredentialStatus[] {
  const entries: CredentialStatus[] = [];
  for (const link of dataset.match()) {
    if (link.predicate.value !== VC_CREDENTIAL_STATUS || link.subject.value !== credentialId) {
      continue;
    }
    const entryId = link.object.value;
    let type = "";
    let statusPurpose = "";
    let statusListIndex = "";
    let statusListCredential = "";
    for (const q of dataset.match()) {
      if (q.subject.value !== entryId) continue;
      if (q.predicate.value === RDF_TYPE && q.object.value === STATUS_LIST_ENTRY) {
        type = "BitstringStatusListEntry";
      } else if (q.predicate.value === STATUS_PURPOSE) {
        statusPurpose = q.object.value;
      } else if (q.predicate.value === STATUS_LIST_INDEX) {
        statusListIndex = q.object.value;
      } else if (q.predicate.value === STATUS_LIST_CREDENTIAL) {
        statusListCredential = q.object.value;
      }
    }
    entries.push({
      ...(link.object.termType === "NamedNode" ? { id: entryId } : {}),
      type,
      statusPurpose,
      statusListIndex,
      statusListCredential,
    });
  }
  return entries;
}

/** Read a structured {@link DataIntegrityProof} from a proof graph node (undefined if malformed). */
function readProof(proof: ProofNode): DataIntegrityProof | undefined {
  const cryptosuite = firstLiteral(proof.cryptosuites);
  const verificationMethod = firstIri(proof.verificationMethods);
  const proofValue = firstLiteral(proof.proofValues);
  // proofPurpose is an IRI in the graph (e.g. sec:assertionMethod).
  const proofPurpose = firstIri(proof.proofPurposes);
  if (
    cryptosuite === undefined ||
    verificationMethod === undefined ||
    proofValue === undefined ||
    proofPurpose === undefined
  ) {
    return undefined;
  }
  const created = firstLiteral(proof.createds);
  return {
    type: "DataIntegrityProof",
    cryptosuite,
    verificationMethod,
    proofPurpose,
    proofValue,
    ...(created !== undefined ? { created } : {}),
  };
}

/**
 * The signature-covered document quads: every quad in the dataset EXCEPT the
 * `sec:proof` links and every quad whose subject is a proof node (the proof graph).
 * Reproduces the claim graph the issuer canonicalized before signing.
 */
function documentQuadsWithoutProofs(
  dataset: DatasetCore,
  proofNodes: readonly ProofNode[],
): Quad[] {
  const proofIds = new Set(proofNodes.map((p) => p.value));
  const out: Quad[] = [];
  for (const quad of dataset.match()) {
    if (quad.predicate.value === SEC_PROOF) continue;
    if (proofIds.has(quad.subject.value)) continue;
    out.push(quad as Quad);
  }
  return out;
}
