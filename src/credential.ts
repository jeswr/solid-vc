// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The Credential ↔ RDF lowering + round-trip, and the agent-authorization
// builder. `credentialToRdf` lowers a structured Credential to quads (via the
// typed GraphBuilder write path — never hand-built triples); `credentialToTurtle`
// /`credentialToJsonLd` serialise; `credentialFromRdf`/`parseCredential` read it
// back. All RDF reads/writes go through src/wrappers.ts.

import { randomUUID } from "node:crypto";
import { parseRdf } from "@jeswr/fetch-rdf";
import type { DatasetCore, Quad } from "@rdfjs/types";
import { serialize } from "./serialize.js";
import type {
  AgentAuthorization,
  Credential,
  CredentialStatus,
  CredentialSubject,
  DataIntegrityProof,
  JsonValue,
  RelatedResource,
  VerifiableCredential,
} from "./types.js";
import {
  DC_CREATED,
  SCHEMA_ENCODING_FORMAT,
  SEC,
  SEC_CRYPTOSUITE,
  SEC_DATA_INTEGRITY_PROOF,
  SEC_DIGEST_MULTIBASE,
  SEC_PROOF,
  SEC_PROOF_PURPOSE,
  SEC_PROOF_VALUE,
  SEC_VERIFICATION_METHOD,
  STATUS_LIST_CREDENTIAL,
  STATUS_LIST_ENTRY,
  STATUS_LIST_INDEX,
  STATUS_PURPOSE,
  SVC_ACTION,
  SVC_AGENT_AUTHORIZATION,
  SVC_AUTHORIZES,
  SVC_INLINE_CONTEXT,
  SVC_POLICY,
  SVC_TARGET,
  VC_CREDENTIAL,
  VC_CREDENTIAL_STATUS,
  VC_CREDENTIAL_SUBJECT,
  VC_DIGEST_SRI,
  VC_ISSUER,
  VC_RELATED_RESOURCE,
  VC_VALID_FROM,
  VC_VALID_UNTIL,
  XSD,
} from "./vocab.js";
import {
  type CredentialNode,
  firstIri,
  firstLiteral,
  GraphBuilder,
  iriRef,
  type NodeRef,
  wrapVc,
} from "./wrappers.js";

/** Whether a string looks like an absolute IRI (scheme + `:`). */
function looksLikeIri(value: string): boolean {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
}

/** Resolve a (possibly relative) credential type to an absolute IRI. */
function typeIri(type: string): string {
  if (type === "VerifiableCredential") return VC_CREDENTIAL;
  if (type === "AgentAuthorizationCredential") return SVC_AGENT_AUTHORIZATION;
  if (looksLikeIri(type)) return type;
  // A bare extension type name: home it under the @jeswr svc extension namespace.
  return `https://w3id.org/jeswr/solid-vc#${type}`;
}

/**
 * Write one credential-subject node (its `id` and arbitrary claims) under the
 * credential `subject` via `cred:credentialSubject`. Claims whose value is an
 * absolute-IRI string are written as IRI objects; everything else as a typed
 * literal (so the JSON booleans/numbers round-trip with their XSD datatype).
 */
function writeSubject(b: GraphBuilder, credential: NodeRef, subject: CredentialSubject): void {
  const node: NodeRef =
    typeof subject.id === "string" && subject.id.length > 0
      ? iriRef(subject.id)
      : b.linkBlankNode(credential, VC_CREDENTIAL_SUBJECT);
  if (node.kind === "iri") {
    b.addIri(credential, VC_CREDENTIAL_SUBJECT, node.value);
  }
  for (const [claim, value] of Object.entries(subject)) {
    if (claim === "id" || value === undefined) continue;
    writeClaim(b, node, claim, value);
  }
}

/** The predicate IRI for a subject claim key (absolute IRI kept; bare name homed). */
function claimPredicate(claim: string): string {
  return looksLikeIri(claim) ? claim : `https://w3id.org/jeswr/solid-vc#${claim}`;
}

/** Write one claim value (string IRI / typed literal / nested object / array). */
function writeClaim(b: GraphBuilder, subject: NodeRef, claim: string, value: JsonValue): void {
  const predicate = claimPredicate(claim);
  if (Array.isArray(value)) {
    for (const item of value) {
      writeClaim(b, subject, claim, item);
    }
    return;
  }
  if (value === null) {
    return; // RDF has no null; omit.
  }
  if (typeof value === "string") {
    if (looksLikeIri(value)) {
      b.addIri(subject, predicate, value);
    } else {
      b.addLiteral(subject, predicate, value);
    }
    return;
  }
  if (typeof value === "boolean") {
    b.addLiteral(subject, predicate, String(value), `${XSD}boolean`);
    return;
  }
  if (typeof value === "number") {
    const dt = Number.isInteger(value) ? `${XSD}integer` : `${XSD}double`;
    b.addLiteral(subject, predicate, String(value), dt);
    return;
  }
  // A nested object → a fresh blank node carrying its own claims.
  const child = b.linkBlankNode(subject, predicate);
  for (const [k, v] of Object.entries(value)) {
    if (v === undefined) continue;
    writeClaim(b, child, k, v as JsonValue);
  }
}

/**
 * Lower a structured {@link Credential} (the UNSIGNED claim graph — no proof) to
 * RDF quads via the typed write path. The credential gets an `@id` (a random
 * `urn:uuid:` when omitted) so it is an addressable named node the proof can bind
 * to. `validFrom` defaults to now ONLY at the {@link issue} step, not here — this
 * is a pure projection of exactly what the caller supplied.
 */
export function credentialToRdf(credential: Credential): Quad[] {
  const id = credential.id ?? `urn:uuid:${randomUUID()}`;
  const subject = iriRef(id);
  const b = new GraphBuilder();
  b.addType(subject, VC_CREDENTIAL);
  for (const t of credential.type ?? []) {
    const iri = typeIri(t);
    if (iri !== VC_CREDENTIAL) b.addType(subject, iri);
  }
  b.addIri(subject, VC_ISSUER, credential.issuer);
  if (credential.validFrom !== undefined) {
    b.addLiteral(subject, VC_VALID_FROM, credential.validFrom, `${XSD}dateTime`);
  }
  if (credential.validUntil !== undefined) {
    b.addLiteral(subject, VC_VALID_UNTIL, credential.validUntil, `${XSD}dateTime`);
  }
  const subjects = Array.isArray(credential.credentialSubject)
    ? credential.credentialSubject
    : [credential.credentialSubject];
  for (const s of subjects) {
    writeSubject(b, subject, s);
  }
  if (credential.credentialStatus !== undefined) {
    const statuses = Array.isArray(credential.credentialStatus)
      ? credential.credentialStatus
      : [credential.credentialStatus];
    for (const status of statuses) {
      writeStatus(b, subject, status);
    }
  }
  if (credential.relatedResource !== undefined) {
    const resources = Array.isArray(credential.relatedResource)
      ? credential.relatedResource
      : [credential.relatedResource];
    for (const resource of resources) {
      writeRelatedResource(b, subject, resource);
    }
  }
  return b.quads();
}

/**
 * Lower one VCDM 2.0 `relatedResource` entry UNDER the credential (so its integrity
 * digest is signed). The resource IRI is the node; `digestSRI` / `digestMultibase` /
 * `mediaType` are literals — the proof then commits to the referenced content.
 */
function writeRelatedResource(
  b: GraphBuilder,
  credential: NodeRef,
  resource: RelatedResource,
): void {
  const node = iriRef(resource.id);
  b.addIri(credential, VC_RELATED_RESOURCE, resource.id);
  if (resource.digestSRI !== undefined) b.addLiteral(node, VC_DIGEST_SRI, resource.digestSRI);
  if (resource.digestMultibase !== undefined) {
    b.addLiteral(node, SEC_DIGEST_MULTIBASE, resource.digestMultibase);
  }
  if (resource.mediaType !== undefined) {
    b.addLiteral(node, SCHEMA_ENCODING_FORMAT, resource.mediaType);
  }
}

/**
 * Lower one `credentialStatus` entry UNDER the credential (so the Data Integrity
 * proof covers it — an attacker cannot strip or swap the revocation pointer without
 * breaking the signature). Written as a `BitstringStatusListEntry` node linked via
 * `cred:credentialStatus`, with the entry `id` as the node IRI when present.
 */
function writeStatus(b: GraphBuilder, credential: NodeRef, status: CredentialStatus): void {
  const node: NodeRef =
    typeof status.id === "string" && status.id.length > 0
      ? iriRef(status.id)
      : b.linkBlankNode(credential, VC_CREDENTIAL_STATUS);
  if (node.kind === "iri") {
    b.addIri(credential, VC_CREDENTIAL_STATUS, node.value);
  }
  b.addType(node, STATUS_LIST_ENTRY);
  b.addLiteral(node, STATUS_PURPOSE, status.statusPurpose);
  b.addLiteral(node, STATUS_LIST_INDEX, String(status.statusListIndex));
  b.addIri(node, STATUS_LIST_CREDENTIAL, status.statusListCredential);
}

/** Serialise a credential's claim graph to Turtle (default) or another n3 format. */
export function credentialToTurtle(credential: Credential, format?: string): Promise<string> {
  return serialize(credentialToRdf(credential), format);
}

/** Resolve a bare `proofPurpose` token (e.g. `assertionMethod`) to its sec: IRI. */
function purposeIri(purpose: string): string {
  return looksLikeIri(purpose) ? purpose : `${SEC}${purpose}`;
}

/** Lower one embedded Data Integrity `proof` node under the credential subject. */
function writeProof(b: GraphBuilder, credential: NodeRef, proof: DataIntegrityProof): void {
  const node = b.linkBlankNode(credential, SEC_PROOF);
  b.addType(node, SEC_DATA_INTEGRITY_PROOF);
  b.addLiteral(node, SEC_CRYPTOSUITE, proof.cryptosuite);
  b.addIri(node, SEC_VERIFICATION_METHOD, proof.verificationMethod);
  b.addIri(node, SEC_PROOF_PURPOSE, purposeIri(proof.proofPurpose));
  if (proof.created !== undefined) {
    b.addLiteral(node, DC_CREATED, proof.created, `${XSD}dateTime`);
  }
  b.addLiteral(node, SEC_PROOF_VALUE, proof.proofValue);
}

/**
 * Lower a SIGNED {@link VerifiableCredential} — the claim graph PLUS its embedded
 * Data Integrity proof(s) — to RDF quads, so an issuer can PUBLISH a signed VC (e.g.
 * a status-list credential) as a dereferenceable RDF document that
 * {@link parseAndVerifyCredential} can re-verify over its exact bytes. The credential
 * `@id` is fixed once (a random `urn:uuid:` only if the VC omits it) so the claim
 * graph and the proof link share the same subject.
 */
export function signedCredentialToRdf(vc: VerifiableCredential): Quad[] {
  const id = vc.id ?? `urn:uuid:${randomUUID()}`;
  const { proof: _proof, ...unsigned } = vc;
  const claimQuads = credentialToRdf({ ...(unsigned as Credential), id });
  const b = new GraphBuilder();
  const subject = iriRef(id);
  const proofs = Array.isArray(vc.proof) ? vc.proof : [vc.proof];
  for (const proof of proofs) {
    writeProof(b, subject, proof);
  }
  return [...claimQuads, ...b.quads()];
}

/** Serialise a SIGNED VC (claim graph + proof) to Turtle (default) or another n3 format. */
export function signedCredentialToTurtle(
  vc: VerifiableCredential,
  format?: string,
): Promise<string> {
  return serialize(signedCredentialToRdf(vc), format);
}

/**
 * Build the VC 2.0 JSON-LD document for a credential's claim graph (no proof): a
 * deterministic projection kept in lock-step with the RDF quads, with the pinned
 * inline `@context`. A consumer can parse it back via `@jeswr/fetch-rdf`.
 */
export function credentialToJsonLd(credential: Credential): Record<string, unknown> {
  const id = credential.id ?? `urn:uuid:${randomUUID()}`;
  const types = ["VerifiableCredential", ...(credential.type ?? [])];
  const doc: Record<string, unknown> = {
    "@context": SVC_INLINE_CONTEXT,
    id,
    type: [...new Set(types)],
    issuer: credential.issuer,
  };
  if (credential.validFrom !== undefined) doc.validFrom = credential.validFrom;
  if (credential.validUntil !== undefined) doc.validUntil = credential.validUntil;
  const subjects = Array.isArray(credential.credentialSubject)
    ? credential.credentialSubject
    : [credential.credentialSubject];
  doc.credentialSubject = subjects.length === 1 ? subjects[0] : subjects;
  if (credential.credentialStatus !== undefined) {
    const statuses = Array.isArray(credential.credentialStatus)
      ? credential.credentialStatus
      : [credential.credentialStatus];
    doc.credentialStatus = statuses.length === 1 ? statuses[0] : statuses;
  }
  if (credential.relatedResource !== undefined) {
    const resources = Array.isArray(credential.relatedResource)
      ? credential.relatedResource
      : [credential.relatedResource];
    doc.relatedResource = resources.length === 1 ? resources[0] : resources;
  }
  return doc;
}

/**
 * Read the credential METADATA (issuer / validity / types / id) back from a
 * parsed credential node. The full `credentialSubject` claim graph is intentionally
 * NOT projected back to a structured object here (it is arbitrary RDF); verification
 * works over the quads directly. Callers that need typed claims use the M-specific
 * helpers (e.g. {@link agentAuthorizationFromRdf}).
 */
export function credentialMetaFromNode(node: CredentialNode): {
  id: string;
  issuer: string | undefined;
  validFrom: string | undefined;
  validUntil: string | undefined;
  types: string[];
} {
  const types: string[] = [];
  for (const t of node.types) {
    if (t.termType === "NamedNode") types.push(t.value);
  }
  return {
    id: node.value,
    issuer: firstIri(node.issuers),
    // validFrom / validUntil are xsd:dateTime literals — read as the first literal.
    validFrom: firstLiteral(node.validFroms),
    validUntil: firstLiteral(node.validUntils),
    types,
  };
}

/** Parse a credential graph (Turtle/JSON-LD string) into an RDF dataset. */
export async function parseCredentialRdf(
  body: string,
  contentType = "text/turtle",
): Promise<DatasetCore> {
  return (await parseRdf(body, contentType)) as unknown as DatasetCore;
}

/** Find the first credential node in a parsed dataset, or `undefined`. */
export function credentialFromRdf(dataset: DatasetCore): CredentialNode | undefined {
  return wrapVc(dataset).credentials()[0];
}

// --- the agent-authorization headline use case ----------------------------

/**
 * Build the structured {@link Credential} for the headline M4 case — "principal
 * authorizes agent for action(s) over target under ODRL policy" — as an
 * `AgentAuthorizationCredential`. The issuer IS the principal (a WebID signs that
 * it delegates to the agent). Compose with `@jeswr/solid-agent-card` (the `agent`
 * IRI) and `@jeswr/solid-odrl` (the `policy` IRI).
 */
export function buildAgentAuthorizationCredential(auth: AgentAuthorization): Credential {
  const actions = Array.isArray(auth.action) ? auth.action : [auth.action];
  const subject: Record<string, JsonValue> = {
    [SVC_AUTHORIZES]: auth.agent,
    [SVC_ACTION]: actions.length === 1 ? (actions[0] as string) : (actions as JsonValue),
  };
  if (auth.target !== undefined) subject[SVC_TARGET] = auth.target;
  // Policy binding (this note's D4): an EMBEDDED policy graph is signed inline; a
  // by-reference IRI is bound by a `relatedResource` digest (below); a bare IRI is
  // emitted only when no digest is supplied — and a conforming verifier rejects it.
  if (auth.embeddedPolicy !== undefined) {
    subject[SVC_POLICY] = auth.embeddedPolicy;
  } else if (auth.policy !== undefined) {
    subject[SVC_POLICY] = auth.policy;
  }
  // The subject `id` is the principal: the WebID that holds the authority and is
  // delegating it. The credential ASSERTS, signed by the same WebID as issuer.
  const credentialSubject: CredentialSubject = { id: auth.principal, ...subject };
  const relatedResource = policyRelatedResource(auth);
  const credential: Credential = {
    issuer: auth.principal,
    type: ["AgentAuthorizationCredential"],
    credentialSubject,
    ...(relatedResource !== undefined ? { relatedResource } : {}),
    ...(auth.id !== undefined ? { id: auth.id } : {}),
    ...(auth.validFrom !== undefined ? { validFrom: auth.validFrom } : {}),
    ...(auth.validUntil !== undefined ? { validUntil: auth.validUntil } : {}),
  };
  return credential;
}

/** The `relatedResource` digest entry for a by-reference policy IRI, if a digest is given. */
function policyRelatedResource(auth: AgentAuthorization): RelatedResource | undefined {
  if (auth.policy === undefined || auth.policyDigest === undefined) return undefined;
  const { digestSRI, digestMultibase, mediaType } = auth.policyDigest;
  return {
    id: auth.policy,
    ...(digestSRI !== undefined ? { digestSRI } : {}),
    ...(digestMultibase !== undefined ? { digestMultibase } : {}),
    ...(mediaType !== undefined ? { mediaType } : {}),
  };
}

/**
 * Read the agent-authorization claim back from a parsed credential node — the
 * typed inverse of {@link buildAgentAuthorizationCredential}. Returns `undefined`
 * if the node is not an `AgentAuthorizationCredential` with the required terms.
 */
export function agentAuthorizationFromRdf(
  node: CredentialNode,
): Pick<AgentAuthorization, "principal" | "agent" | "action" | "target" | "policy"> | undefined {
  const meta = credentialMetaFromNode(node);
  if (!meta.types.includes(SVC_AGENT_AUTHORIZATION)) return undefined;
  const subjectTerm = [...node.subjects].find((t) => t.termType === "NamedNode");
  if (subjectTerm === undefined) return undefined;
  const subjectIri = subjectTerm.value;
  const dataset = node.dataset as unknown as DatasetCore;
  const reads = readSubjectClaims(dataset, subjectIri);
  if (reads.authorizes === undefined || reads.action.length === 0) return undefined;
  return {
    principal: subjectIri,
    agent: reads.authorizes,
    action: reads.action.length === 1 ? (reads.action[0] as string) : reads.action,
    ...(reads.target !== undefined ? { target: reads.target } : {}),
    ...(reads.policy !== undefined ? { policy: reads.policy } : {}),
  };
}

/** Read the agent-authz claims for a subject IRI directly from the quads. */
function readSubjectClaims(
  dataset: DatasetCore,
  subjectIri: string,
): { authorizes?: string; action: string[]; target?: string; policy?: string } {
  let authorizes: string | undefined;
  const action: string[] = [];
  let target: string | undefined;
  let policy: string | undefined;
  for (const quad of dataset.match()) {
    if (quad.subject.termType !== "NamedNode" || quad.subject.value !== subjectIri) continue;
    if (quad.object.termType !== "NamedNode") continue;
    switch (quad.predicate.value) {
      case SVC_AUTHORIZES:
        authorizes = quad.object.value;
        break;
      case SVC_ACTION:
        action.push(quad.object.value);
        break;
      case SVC_TARGET:
        target = quad.object.value;
        break;
      case SVC_POLICY:
        policy = quad.object.value;
        break;
      default:
        break;
    }
  }
  return {
    ...(authorizes !== undefined ? { authorizes } : {}),
    action,
    ...(target !== undefined ? { target } : {}),
    ...(policy !== undefined ? { policy } : {}),
  };
}
