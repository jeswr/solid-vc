// src/canonicalize.ts
import { createHash } from "node:crypto";
import { canonize } from "rdf-canonize";
async function canonicalNQuads(quads) {
  return await canonize(quads, {
    algorithm: "RDFC-1.0",
    format: "application/n-quads"
  });
}
function sha256(input) {
  return new Uint8Array(createHash("sha256").update(input, "utf8").digest());
}
async function dataIntegrityHash(documentQuads, proofOptionsQuads2) {
  const docCanon = await canonicalNQuads(documentQuads);
  const proofCanon = await canonicalNQuads(proofOptionsQuads2);
  const proofHash = sha256(proofCanon);
  const docHash = sha256(docCanon);
  const out = new Uint8Array(proofHash.length + docHash.length);
  out.set(proofHash, 0);
  out.set(docHash, proofHash.length);
  return out;
}

// node_modules/@jeswr/fetch-rdf/dist/parse.js
import contentType from "content-type";
import { Store, StreamParser } from "n3";
import { JsonLdParser } from "jsonld-streaming-parser";

// node_modules/@jeswr/fetch-rdf/dist/errors.js
var RdfFetchError = class extends Error {
  /** The original cause, if any (e.g. a network error or parser exception). */
  cause;
  /** HTTP status code from a non-2xx response, if applicable. */
  status;
  /** The final request URL (after redirects), if known. */
  url;
  /** Raw `Content-Type` header from the response, if known. */
  contentType;
  constructor(message, options = {}) {
    super(message);
    this.name = "RdfFetchError";
    if (options.cause !== void 0)
      this.cause = options.cause;
    if (options.status !== void 0)
      this.status = options.status;
    if (options.url !== void 0)
      this.url = options.url;
    if (options.contentType !== void 0)
      this.contentType = options.contentType;
  }
};

// node_modules/@jeswr/fetch-rdf/dist/parse.js
var SUPPORTED_RDF_MEDIA_TYPES = [
  "text/turtle",
  "application/n-triples",
  "application/n-quads",
  "application/trig",
  "application/ld+json"
];
var N3_FAMILY = /* @__PURE__ */ new Set([
  "text/turtle",
  "application/n-triples",
  "application/n-quads",
  "application/trig"
]);
var JSON_LD_FAMILY = /* @__PURE__ */ new Set([
  "application/ld+json"
]);
async function parseRdf(body, contentTypeHeader, options = {}) {
  const rawHeader = contentTypeHeader ?? "text/turtle";
  let mediaType;
  try {
    mediaType = contentType.parse(rawHeader).type;
  } catch (cause) {
    throw new RdfFetchError(`Invalid Content-Type header: "${rawHeader}".`, { cause, contentType: rawHeader });
  }
  const baseIRI = options.baseIRI;
  let parser;
  if (N3_FAMILY.has(mediaType)) {
    parser = new StreamParser({
      format: mediaType,
      ...baseIRI !== void 0 && { baseIRI }
    });
  } else if (JSON_LD_FAMILY.has(mediaType)) {
    parser = new JsonLdParser({
      ...baseIRI !== void 0 && { baseIRI }
    });
  } else {
    throw new RdfFetchError(`Unsupported RDF media type: "${mediaType}". Supported: ${SUPPORTED_RDF_MEDIA_TYPES.join(", ")}.`, { contentType: rawHeader, ...baseIRI !== void 0 && { url: baseIRI } });
  }
  const storePromise = collectIntoStore(parser);
  try {
    await pumpBody(parser, body);
    return await storePromise;
  } catch (cause) {
    if (cause instanceof RdfFetchError)
      throw cause;
    throw new RdfFetchError(`Failed to parse ${mediaType} body${baseIRI ? ` at ${baseIRI}` : ""}.`, { cause, contentType: rawHeader, ...baseIRI !== void 0 && { url: baseIRI } });
  }
}
function collectIntoStore(parser) {
  return new Promise((resolve, reject) => {
    const store = new Store();
    parser.on("data", (quad) => {
      store.addQuad(quad);
    });
    parser.on("error", reject);
    parser.on("end", () => {
      resolve(store);
    });
  });
}
async function pumpBody(parser, body) {
  if (typeof body === "string") {
    parser.end(body);
    return;
  }
  let parserError = null;
  const onParserError = (err) => {
    parserError = err;
  };
  parser.on("error", onParserError);
  const reader = body.getReader();
  try {
    const decoder = new TextDecoder();
    for (; ; ) {
      if (parserError)
        throw parserError;
      const { done, value } = await reader.read();
      if (done)
        break;
      if (value === void 0)
        continue;
      const text = decoder.decode(value, { stream: true });
      if (text.length === 0)
        continue;
      if (!parser.write(text))
        await waitForDrain(parser);
    }
    if (parserError)
      throw parserError;
    const tail = decoder.decode();
    if (tail.length > 0)
      parser.write(tail);
    parser.end();
  } catch (err) {
    parser.destroy(err instanceof Error ? err : new Error(String(err)));
    try {
      await reader.cancel();
    } catch {
    }
    throw err;
  } finally {
    parser.off("error", onParserError);
    reader.releaseLock();
  }
}
function waitForDrain(parser) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      parser.off("drain", onDrain);
      parser.off("error", onError);
    };
    const onDrain = () => {
      cleanup();
      resolve();
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    parser.once("drain", onDrain);
    parser.once("error", onError);
  });
}

// src/vocab.ts
var VC = "https://www.w3.org/2018/credentials#";
var VC_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
var SEC = "https://w3id.org/security#";
var XSD = "http://www.w3.org/2001/XMLSchema#";
var RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
var RDFS = "http://www.w3.org/2000/01/rdf-schema#";
var ACL = "http://www.w3.org/ns/auth/acl#";
var ODRL = "http://www.w3.org/ns/odrl/2/";
var SCHEMA = "https://schema.org/";
var SVC = "https://w3id.org/jeswr/solid-vc#";
var RDF_TYPE = `${RDF}type`;
var VC_CREDENTIAL = `${VC}VerifiableCredential`;
var VC_PRESENTATION = `${VC}VerifiablePresentation`;
var VC_ISSUER = `${VC}issuer`;
var VC_CREDENTIAL_SUBJECT = `${VC}credentialSubject`;
var VC_VALID_FROM = `${VC}validFrom`;
var VC_VALID_UNTIL = `${VC}validUntil`;
var VC_CREDENTIAL_STATUS = `${VC}credentialStatus`;
var VC_RELATED_RESOURCE = `${VC}relatedResource`;
var VC_DIGEST_SRI = `${VC}digestSRI`;
var SEC_DIGEST_MULTIBASE = `${SEC}digestMultibase`;
var SCHEMA_ENCODING_FORMAT = `${SCHEMA}encodingFormat`;
var VC_VERIFIABLE_CREDENTIAL = `${VC}verifiableCredential`;
var VC_HOLDER = `${VC}holder`;
var SEC_PROOF = `${SEC}proof`;
var SEC_DATA_INTEGRITY_PROOF = `${SEC}DataIntegrityProof`;
var SEC_CRYPTOSUITE = `${SEC}cryptosuite`;
var SEC_PROOF_VALUE = `${SEC}proofValue`;
var SEC_VERIFICATION_METHOD = `${SEC}verificationMethod`;
var SEC_PROOF_PURPOSE = `${SEC}proofPurpose`;
var SEC_CHALLENGE = `${SEC}challenge`;
var SEC_DOMAIN = `${SEC}domain`;
var DC_CREATED = "http://purl.org/dc/terms/created";
var STATUS = "https://www.w3.org/ns/credentials/status#";
var STATUS_LIST_ENTRY = `${STATUS}BitstringStatusListEntry`;
var STATUS_LIST = `${STATUS}BitstringStatusList`;
var STATUS_PURPOSE = `${STATUS}statusPurpose`;
var STATUS_LIST_INDEX = `${STATUS}statusListIndex`;
var STATUS_LIST_CREDENTIAL = `${STATUS}statusListCredential`;
var STATUS_ENCODED_LIST = `${STATUS}encodedList`;
var SVC_AGENT_AUTHORIZATION = `${SVC}AgentAuthorizationCredential`;
var SVC_AUTHORIZES = `${SVC}authorizes`;
var SVC_ACTION = `${SVC}action`;
var SVC_TARGET = `${SVC}target`;
var SVC_POLICY = `${SVC}policy`;
var SVC_TERMS = {
  svc: SVC,
  acl: ACL,
  odrl: ODRL,
  schema: SCHEMA,
  AgentAuthorizationCredential: SVC_AGENT_AUTHORIZATION,
  authorizes: { "@id": SVC_AUTHORIZES, "@type": "@id" },
  action: { "@id": SVC_ACTION, "@type": "@id" },
  target: { "@id": SVC_TARGET, "@type": "@id" },
  policy: { "@id": SVC_POLICY, "@type": "@id" }
};
var SVC_INLINE_CONTEXT = [
  VC_V2_CONTEXT,
  SVC_TERMS
];

// src/controller.ts
function isHttpIri(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}
function documentUrl(iri) {
  const url = new URL(iri);
  url.hash = "";
  return url.toString();
}
function relationshipIriForPurpose(purpose) {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(purpose) ? purpose : `${SEC}${purpose}`;
}
function prefixControlledBy(verificationMethod, issuer) {
  if (verificationMethod === issuer) return true;
  return verificationMethod.startsWith(`${issuer}#`) || verificationMethod.startsWith(`${issuer}/`);
}
function documentResolvedControlledBy(fetch, expectedProofPurpose = "assertionMethod") {
  const relationship = relationshipIriForPurpose(expectedProofPurpose);
  return async (verificationMethod, issuer) => {
    if (!isHttpIri(verificationMethod) || !isHttpIri(issuer)) return false;
    let dataset;
    try {
      const docUrl = documentUrl(issuer);
      const response = await fetch(docUrl);
      if (!response.ok) return false;
      const body = await response.text();
      const contentType2 = response.headers.get("content-type") ?? "text/turtle";
      dataset = await parseRdf(body, contentType2, {
        baseIRI: docUrl
      });
    } catch {
      return false;
    }
    return documentAssertsRelationship(dataset, issuer, relationship, verificationMethod);
  };
}
function documentAssertsRelationship(dataset, issuer, relationship, verificationMethod) {
  for (const quad of dataset.match()) {
    if (quad.subject.termType === "NamedNode" && quad.object.termType === "NamedNode" && quad.predicate.value === relationship && quad.subject.value === issuer && quad.object.value === verificationMethod) {
      return true;
    }
  }
  return false;
}

// src/credential.ts
import { randomUUID } from "node:crypto";

// node_modules/@jeswr/rdf-serialize/dist/serialize.js
import { Writer } from "n3";
var DEFAULT_FORMAT = "text/turtle";
function serialize(quads, options) {
  const format = options?.format ?? DEFAULT_FORMAT;
  const prefixes = options?.prefixes ?? {};
  const emptyAsEmptyString = options?.emptyAsEmptyString ?? true;
  if (emptyAsEmptyString && quads.length === 0) {
    return Promise.resolve("");
  }
  return new Promise((resolve, reject) => {
    const writer = new Writer({ format, prefixes });
    writer.addQuads(quads);
    writer.end((error, result) => {
      if (error) {
        reject(error);
      } else {
        resolve(result);
      }
    });
  });
}
function legacySerialize(quads, format = DEFAULT_FORMAT, prefixes = {}, emptyAsEmptyString = true) {
  return serialize(quads, { format, prefixes, emptyAsEmptyString });
}

// src/serialize.ts
var PREFIXES = {
  cred: VC,
  sec: SEC,
  svc: SVC,
  acl: ACL,
  odrl: ODRL,
  schema: SCHEMA,
  xsd: XSD,
  rdf: RDF,
  rdfs: RDFS,
  dcterms: DC_CREATED.replace("created", "")
};
function serialize2(quads, format = "text/turtle") {
  return legacySerialize(quads, format, PREFIXES);
}

// src/wrappers.ts
import {
  BlankNodeFrom,
  DatasetWrapper,
  LiteralFrom,
  NamedNodeFrom,
  SetFrom,
  TermAs,
  TermFrom,
  TermWrapper
} from "@rdfjs/wrapper";
import { DataFactory, Store as Store2 } from "n3";
function objectTerms(node, predicate) {
  return SetFrom.subjectPredicate(node, predicate, TermAs.instance(TermWrapper), TermFrom.instance);
}
var ProofNode = class extends TermWrapper {
  get types() {
    return objectTerms(this, RDF_TYPE);
  }
  get cryptosuites() {
    return objectTerms(this, SEC_CRYPTOSUITE);
  }
  get verificationMethods() {
    return objectTerms(this, SEC_VERIFICATION_METHOD);
  }
  get proofPurposes() {
    return objectTerms(this, SEC_PROOF_PURPOSE);
  }
  get proofValues() {
    return objectTerms(this, SEC_PROOF_VALUE);
  }
  get createds() {
    return objectTerms(this, DC_CREATED);
  }
};
var CredentialNode = class extends TermWrapper {
  get types() {
    return objectTerms(this, RDF_TYPE);
  }
  get issuers() {
    return objectTerms(this, VC_ISSUER);
  }
  get subjects() {
    return objectTerms(this, VC_CREDENTIAL_SUBJECT);
  }
  get validFroms() {
    return objectTerms(this, VC_VALID_FROM);
  }
  get validUntils() {
    return objectTerms(this, VC_VALID_UNTIL);
  }
  get proofs() {
    return SetFrom.subjectPredicate(this, SEC_PROOF, TermAs.instance(ProofNode), TermFrom.instance);
  }
};
var PresentationNode = class extends TermWrapper {
  get types() {
    return objectTerms(this, RDF_TYPE);
  }
  get holders() {
    return objectTerms(this, VC_HOLDER);
  }
  get credentials() {
    return SetFrom.subjectPredicate(
      this,
      VC_VERIFIABLE_CREDENTIAL,
      TermAs.instance(CredentialNode),
      TermFrom.instance
    );
  }
  get proofs() {
    return SetFrom.subjectPredicate(this, SEC_PROOF, TermAs.instance(ProofNode), TermFrom.instance);
  }
};
var VcDataset = class extends DatasetWrapper {
  /** Every `cred:VerifiableCredential` subject in the dataset. */
  credentials() {
    return [...this.instancesOf(VC_CREDENTIAL, CredentialNode)];
  }
  /** Every `cred:VerifiablePresentation` subject in the dataset. */
  presentations() {
    return [...this.instancesOf(VC_PRESENTATION, PresentationNode)];
  }
};
function wrapVc(dataset) {
  return new VcDataset(dataset, DataFactory);
}
function firstIri(terms) {
  for (const term of terms) {
    if (term.termType === "NamedNode") {
      return term.value;
    }
  }
  return void 0;
}
function firstLiteral(terms) {
  for (const term of terms) {
    if (term.termType === "Literal") {
      return term.value;
    }
  }
  return void 0;
}
function iriRef(iri) {
  return { kind: "iri", value: iri };
}
function normalize(subject) {
  return typeof subject === "string" ? { kind: "iri", value: subject } : subject;
}
var GraphBuilder = class {
  store = new Store2();
  factory = DataFactory;
  /** Materialise a {@link NodeRef} to its RDF/JS term. */
  subjectTerm(ref) {
    return ref.kind === "iri" ? NamedNodeFrom.string(ref.value, this.factory) : BlankNodeFrom.string(ref.value, this.factory);
  }
  /** Add `(subject, rdf:type, classIri)`. */
  addType(subject, classIri) {
    this.addIri(subject, RDF_TYPE, classIri);
  }
  /** Add `(subject, predicate, object-IRI)`. */
  addIri(subject, predicate, objectIri) {
    const s = this.subjectTerm(normalize(subject));
    const p = NamedNodeFrom.string(predicate, this.factory);
    const o = NamedNodeFrom.string(objectIri, this.factory);
    this.store.add(this.factory.quad(s, p, o));
  }
  /** Add `(subject, predicate, literal)` with an optional datatype IRI. */
  addLiteral(subject, predicate, value, datatypeIri) {
    const s = this.subjectTerm(normalize(subject));
    const p = NamedNodeFrom.string(predicate, this.factory);
    const o = datatypeIri === void 0 ? LiteralFrom.string(value, this.factory) : this.factory.literal(
      value,
      NamedNodeFrom.string(datatypeIri, this.factory)
    );
    this.store.add(this.factory.quad(s, p, o));
  }
  /**
   * Mint a fresh blank node, link it `(subject, predicate, _:b)`, and return a
   * {@link NodeRef} to the new blank node (so subsequent writes target it
   * unambiguously as a blank, never as an IRI).
   */
  linkBlankNode(subject, predicate) {
    const s = this.subjectTerm(normalize(subject));
    const blank = BlankNodeFrom.string(void 0, this.factory);
    const p = NamedNodeFrom.string(predicate, this.factory);
    this.store.add(this.factory.quad(s, p, blank));
    return { kind: "blank", value: blank.value };
  }
  /** The underlying store (a DatasetCore). */
  dataset() {
    return this.store;
  }
  /** The accumulated quads. */
  quads() {
    return [...this.store];
  }
};

// src/credential.ts
function looksLikeIri(value) {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
}
function typeIri(type) {
  if (type === "VerifiableCredential") return VC_CREDENTIAL;
  if (type === "AgentAuthorizationCredential") return SVC_AGENT_AUTHORIZATION;
  if (looksLikeIri(type)) return type;
  return `https://w3id.org/jeswr/solid-vc#${type}`;
}
function writeSubject(b, credential, subject) {
  const node = typeof subject.id === "string" && subject.id.length > 0 ? iriRef(subject.id) : b.linkBlankNode(credential, VC_CREDENTIAL_SUBJECT);
  if (node.kind === "iri") {
    b.addIri(credential, VC_CREDENTIAL_SUBJECT, node.value);
  }
  for (const [claim, value] of Object.entries(subject)) {
    if (claim === "id" || value === void 0) continue;
    writeClaim(b, node, claim, value);
  }
}
function claimPredicate(claim) {
  return looksLikeIri(claim) ? claim : `https://w3id.org/jeswr/solid-vc#${claim}`;
}
function writeClaim(b, subject, claim, value) {
  const predicate = claimPredicate(claim);
  if (Array.isArray(value)) {
    for (const item of value) {
      writeClaim(b, subject, claim, item);
    }
    return;
  }
  if (value === null) {
    return;
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
  const child = b.linkBlankNode(subject, predicate);
  for (const [k, v] of Object.entries(value)) {
    if (v === void 0) continue;
    writeClaim(b, child, k, v);
  }
}
function credentialToRdf(credential) {
  const id = credential.id ?? `urn:uuid:${randomUUID()}`;
  const subject = iriRef(id);
  const b = new GraphBuilder();
  b.addType(subject, VC_CREDENTIAL);
  for (const t of credential.type ?? []) {
    const iri = typeIri(t);
    if (iri !== VC_CREDENTIAL) b.addType(subject, iri);
  }
  b.addIri(subject, VC_ISSUER, credential.issuer);
  if (credential.validFrom !== void 0) {
    b.addLiteral(subject, VC_VALID_FROM, credential.validFrom, `${XSD}dateTime`);
  }
  if (credential.validUntil !== void 0) {
    b.addLiteral(subject, VC_VALID_UNTIL, credential.validUntil, `${XSD}dateTime`);
  }
  const subjects = Array.isArray(credential.credentialSubject) ? credential.credentialSubject : [credential.credentialSubject];
  for (const s of subjects) {
    writeSubject(b, subject, s);
  }
  if (credential.credentialStatus !== void 0) {
    const statuses = Array.isArray(credential.credentialStatus) ? credential.credentialStatus : [credential.credentialStatus];
    for (const status of statuses) {
      writeStatus(b, subject, status);
    }
  }
  if (credential.relatedResource !== void 0) {
    const resources = Array.isArray(credential.relatedResource) ? credential.relatedResource : [credential.relatedResource];
    for (const resource of resources) {
      writeRelatedResource(b, subject, resource);
    }
  }
  return b.quads();
}
function writeRelatedResource(b, credential, resource) {
  const node = iriRef(resource.id);
  b.addIri(credential, VC_RELATED_RESOURCE, resource.id);
  if (resource.digestSRI !== void 0) b.addLiteral(node, VC_DIGEST_SRI, resource.digestSRI);
  if (resource.digestMultibase !== void 0) {
    b.addLiteral(node, SEC_DIGEST_MULTIBASE, resource.digestMultibase);
  }
  if (resource.mediaType !== void 0) {
    b.addLiteral(node, SCHEMA_ENCODING_FORMAT, resource.mediaType);
  }
}
function writeStatus(b, credential, status) {
  const node = typeof status.id === "string" && status.id.length > 0 ? iriRef(status.id) : b.linkBlankNode(credential, VC_CREDENTIAL_STATUS);
  if (node.kind === "iri") {
    b.addIri(credential, VC_CREDENTIAL_STATUS, node.value);
  }
  b.addType(node, STATUS_LIST_ENTRY);
  b.addLiteral(node, STATUS_PURPOSE, status.statusPurpose);
  b.addLiteral(node, STATUS_LIST_INDEX, String(status.statusListIndex));
  b.addIri(node, STATUS_LIST_CREDENTIAL, status.statusListCredential);
}
function credentialToTurtle(credential, format) {
  return serialize2(credentialToRdf(credential), format);
}
function purposeIri(purpose) {
  return looksLikeIri(purpose) ? purpose : `${SEC}${purpose}`;
}
function writeProof(b, credential, proof) {
  const node = b.linkBlankNode(credential, SEC_PROOF);
  b.addType(node, SEC_DATA_INTEGRITY_PROOF);
  b.addLiteral(node, SEC_CRYPTOSUITE, proof.cryptosuite);
  b.addIri(node, SEC_VERIFICATION_METHOD, proof.verificationMethod);
  b.addIri(node, SEC_PROOF_PURPOSE, purposeIri(proof.proofPurpose));
  if (proof.created !== void 0) {
    b.addLiteral(node, DC_CREATED, proof.created, `${XSD}dateTime`);
  }
  b.addLiteral(node, SEC_PROOF_VALUE, proof.proofValue);
}
function signedCredentialToRdf(vc) {
  const id = vc.id ?? `urn:uuid:${randomUUID()}`;
  const { proof: _proof, ...unsigned2 } = vc;
  const claimQuads = credentialToRdf({ ...unsigned2, id });
  const b = new GraphBuilder();
  const subject = iriRef(id);
  const proofs = Array.isArray(vc.proof) ? vc.proof : [vc.proof];
  for (const proof of proofs) {
    writeProof(b, subject, proof);
  }
  return [...claimQuads, ...b.quads()];
}
function signedCredentialToTurtle(vc, format) {
  return serialize2(signedCredentialToRdf(vc), format);
}
function credentialToJsonLd(credential) {
  const id = credential.id ?? `urn:uuid:${randomUUID()}`;
  const types = ["VerifiableCredential", ...credential.type ?? []];
  const doc = {
    "@context": SVC_INLINE_CONTEXT,
    id,
    type: [...new Set(types)],
    issuer: credential.issuer
  };
  if (credential.validFrom !== void 0) doc.validFrom = credential.validFrom;
  if (credential.validUntil !== void 0) doc.validUntil = credential.validUntil;
  const subjects = Array.isArray(credential.credentialSubject) ? credential.credentialSubject : [credential.credentialSubject];
  doc.credentialSubject = subjects.length === 1 ? subjects[0] : subjects;
  if (credential.credentialStatus !== void 0) {
    const statuses = Array.isArray(credential.credentialStatus) ? credential.credentialStatus : [credential.credentialStatus];
    doc.credentialStatus = statuses.length === 1 ? statuses[0] : statuses;
  }
  if (credential.relatedResource !== void 0) {
    const resources = Array.isArray(credential.relatedResource) ? credential.relatedResource : [credential.relatedResource];
    doc.relatedResource = resources.length === 1 ? resources[0] : resources;
  }
  return doc;
}
function credentialMetaFromNode(node) {
  const types = [];
  for (const t of node.types) {
    if (t.termType === "NamedNode") types.push(t.value);
  }
  return {
    id: node.value,
    issuer: firstIri(node.issuers),
    // validFrom / validUntil are xsd:dateTime literals — read as the first literal.
    validFrom: firstLiteral(node.validFroms),
    validUntil: firstLiteral(node.validUntils),
    types
  };
}
async function parseCredentialRdf(body, contentType2 = "text/turtle") {
  return await parseRdf(body, contentType2);
}
function credentialFromRdf(dataset) {
  return wrapVc(dataset).credentials()[0];
}
function buildAgentAuthorizationCredential(auth) {
  const actions = Array.isArray(auth.action) ? auth.action : [auth.action];
  const subject = {
    [SVC_AUTHORIZES]: auth.agent,
    [SVC_ACTION]: actions.length === 1 ? actions[0] : actions
  };
  if (auth.target !== void 0) subject[SVC_TARGET] = auth.target;
  if (auth.embeddedPolicy !== void 0) {
    subject[SVC_POLICY] = auth.embeddedPolicy;
  } else if (auth.policy !== void 0) {
    subject[SVC_POLICY] = auth.policy;
  }
  const credentialSubject = { id: auth.principal, ...subject };
  const relatedResource = policyRelatedResource(auth);
  const credential = {
    issuer: auth.principal,
    type: ["AgentAuthorizationCredential"],
    credentialSubject,
    ...relatedResource !== void 0 ? { relatedResource } : {},
    ...auth.id !== void 0 ? { id: auth.id } : {},
    ...auth.validFrom !== void 0 ? { validFrom: auth.validFrom } : {},
    ...auth.validUntil !== void 0 ? { validUntil: auth.validUntil } : {}
  };
  return credential;
}
function policyRelatedResource(auth) {
  if (auth.policy === void 0 || auth.policyDigest === void 0) return void 0;
  const { digestSRI, digestMultibase, mediaType } = auth.policyDigest;
  return {
    id: auth.policy,
    ...digestSRI !== void 0 ? { digestSRI } : {},
    ...digestMultibase !== void 0 ? { digestMultibase } : {},
    ...mediaType !== void 0 ? { mediaType } : {}
  };
}
function agentAuthorizationFromRdf(node) {
  const meta = credentialMetaFromNode(node);
  if (!meta.types.includes(SVC_AGENT_AUTHORIZATION)) return void 0;
  const subjectTerm = [...node.subjects].find((t) => t.termType === "NamedNode");
  if (subjectTerm === void 0) return void 0;
  const subjectIri = subjectTerm.value;
  const dataset = node.dataset;
  const reads = readSubjectClaims(dataset, subjectIri);
  if (reads.authorizes === void 0 || reads.action.length === 0) return void 0;
  return {
    principal: subjectIri,
    agent: reads.authorizes,
    action: reads.action.length === 1 ? reads.action[0] : reads.action,
    ...reads.target !== void 0 ? { target: reads.target } : {},
    ...reads.policy !== void 0 ? { policy: reads.policy } : {}
  };
}
function readSubjectClaims(dataset, subjectIri) {
  let authorizes;
  const action = [];
  let target;
  let policy;
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
    ...authorizes !== void 0 ? { authorizes } : {},
    action,
    ...target !== void 0 ? { target } : {},
    ...policy !== void 0 ? { policy } : {}
  };
}

// src/issue.ts
import { randomUUID as randomUUID2 } from "node:crypto";

// src/multibase.ts
import { base58btc } from "multiformats/bases/base58";
function base58btcEncode(bytes) {
  return base58btc.encode(bytes);
}
function base58btcDecode(value) {
  return base58btc.decode(value);
}

// src/proof.ts
var SuiteRegistry = class {
  suites = /* @__PURE__ */ new Map();
  /** Register a suite (overwrites any prior suite with the same cryptosuite id). */
  register(suite) {
    this.suites.set(suite.cryptosuite, suite);
    return this;
  }
  /** The suite for a cryptosuite id, or `undefined` if none is registered. */
  get(cryptosuite) {
    return this.suites.get(cryptosuite);
  }
  /** Every registered cryptosuite id. */
  list() {
    return [...this.suites.keys()];
  }
};
function proofOptionsQuads(proof) {
  const b = new GraphBuilder();
  const node = { kind: "blank", value: "_:proof" };
  b.addType(node, "https://w3id.org/security#DataIntegrityProof");
  b.addLiteral(node, SEC_CRYPTOSUITE, proof.cryptosuite);
  b.addIri(node, SEC_VERIFICATION_METHOD, proof.verificationMethod);
  b.addIri(node, SEC_PROOF_PURPOSE, purposeIri2(proof.proofPurpose));
  if (proof.created !== void 0) {
    b.addLiteral(node, DC_CREATED, proof.created, "http://www.w3.org/2001/XMLSchema#dateTime");
  }
  if (proof.challenge !== void 0) b.addLiteral(node, SEC_CHALLENGE, proof.challenge);
  if (proof.domain !== void 0) b.addLiteral(node, SEC_DOMAIN, proof.domain);
  return b.quads();
}
function purposeIri2(purpose) {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(purpose) ? purpose : `https://w3id.org/security#${purpose}`;
}
function algorithmFor(cryptosuite) {
  switch (cryptosuite) {
    case "eddsa-rdfc-2022":
      return "Ed25519";
    case "ecdsa-rdfc-2019":
      return { name: "ECDSA", hash: "SHA-256" };
    default:
      throw new Error(`DataIntegritySuite: unsupported cryptosuite "${cryptosuite}"`);
  }
}
var DataIntegritySuite = class {
  cryptosuite;
  constructor(cryptosuite = "eddsa-rdfc-2022") {
    this.cryptosuite = cryptosuite;
    algorithmFor(cryptosuite);
  }
  async sign(documentQuads, options) {
    const key = options.key;
    if (key?.privateKey === void 0 || key.verificationMethod === void 0) {
      throw new Error("DataIntegritySuite.sign: options.key must be a KeyPair");
    }
    const created = options.created.toISOString();
    const optionsNoValue = {
      type: "DataIntegrityProof",
      cryptosuite: this.cryptosuite,
      verificationMethod: key.verificationMethod,
      proofPurpose: options.proofPurpose,
      created,
      ...options.challenge !== void 0 ? { challenge: options.challenge } : {},
      ...options.domain !== void 0 ? { domain: options.domain } : {}
    };
    const hash = await dataIntegrityHash(documentQuads, proofOptionsQuads(optionsNoValue));
    const algorithm = algorithmFor(this.cryptosuite);
    const signature = new Uint8Array(
      await crypto.subtle.sign(algorithm, key.privateKey, hash)
    );
    return { ...optionsNoValue, proofValue: base58btcEncode(signature) };
  }
  async verify(documentQuads, proof, options) {
    if (proof.type !== "DataIntegrityProof") return false;
    if (proof.cryptosuite !== this.cryptosuite) return false;
    const publicKey = await options.resolveKey(proof.verificationMethod);
    if (publicKey === void 0) return false;
    let signature;
    try {
      signature = base58btcDecode(proof.proofValue);
    } catch {
      return false;
    }
    const optionsNoValue = {
      type: "DataIntegrityProof",
      cryptosuite: proof.cryptosuite,
      verificationMethod: proof.verificationMethod,
      proofPurpose: proof.proofPurpose,
      ...proof.created !== void 0 ? { created: proof.created } : {},
      ...proof.challenge !== void 0 ? { challenge: proof.challenge } : {},
      ...proof.domain !== void 0 ? { domain: proof.domain } : {}
    };
    const hash = await dataIntegrityHash(documentQuads, proofOptionsQuads(optionsNoValue));
    const algorithm = algorithmFor(this.cryptosuite);
    try {
      return await crypto.subtle.verify(
        algorithm,
        publicKey,
        signature,
        hash
      );
    } catch {
      return false;
    }
  }
};
function defaultSuiteRegistry() {
  return new SuiteRegistry().register(new DataIntegritySuite("eddsa-rdfc-2022")).register(new DataIntegritySuite("ecdsa-rdfc-2019"));
}

// src/issue.ts
async function issue(input) {
  const suite = input.suite ?? new DataIntegritySuite("eddsa-rdfc-2022");
  const created = input.options?.created ?? /* @__PURE__ */ new Date();
  const proofPurpose = input.options?.proofPurpose ?? "assertionMethod";
  const credential = {
    ...input.credential,
    id: input.credential.id ?? `urn:uuid:${randomUUID2()}`,
    validFrom: input.credential.validFrom ?? created.toISOString()
  };
  const documentQuads = credentialToRdf(credential);
  const proof = await suite.sign(documentQuads, {
    key: input.key,
    proofPurpose,
    created
  });
  return { ...credential, proof };
}
async function issueAgentAuthorization(auth, key, opts) {
  const credential = buildAgentAuthorizationCredential(auth);
  return issue({
    credential,
    key,
    ...opts?.suite !== void 0 ? { suite: opts.suite } : {},
    ...opts?.options !== void 0 ? { options: opts.options } : {}
  });
}

// src/keys.ts
import { exportJWK, generateKeyPair, importJWK } from "jose";
function paramsFor(type) {
  if (type === "Ed25519") {
    return {
      alg: "EdDSA",
      cryptosuite: "eddsa-rdfc-2022",
      options: { crv: "Ed25519", extractable: true }
    };
  }
  return { alg: "ES256", cryptosuite: "ecdsa-rdfc-2019", options: { extractable: true } };
}
async function generateKeyPairForSuite(verificationMethod, type = "Ed25519") {
  const { alg, options } = paramsFor(type);
  const { privateKey, publicKey } = await generateKeyPair(alg, options);
  return {
    verificationMethod,
    privateKey,
    publicKey
  };
}
function cryptosuiteForKeyType(type) {
  return paramsFor(type).cryptosuite;
}
async function exportPublicJwk(key) {
  return exportJWK(key.publicKey);
}
async function exportPrivateJwk(key) {
  return exportJWK(key.privateKey);
}
async function importPublicKey(jwk) {
  const alg = algForJwk(jwk);
  return await importJWK(jwk, alg, { extractable: true });
}
async function importKeyPair(verificationMethod, privateJwk) {
  const alg = algForJwk(privateJwk);
  const privateKey = await importJWK(privateJwk, alg, { extractable: true });
  const { d: _d, ...pub } = privateJwk;
  const publicKey = await importJWK(pub, alg, { extractable: true });
  return { verificationMethod, privateKey, publicKey };
}
function algForJwk(jwk) {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "EdDSA";
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ES256";
  throw new Error(`unsupported JWK: kty=${jwk.kty} crv=${jwk.crv ?? "?"}`);
}

// src/policy-binding.ts
import { createHash as createHash2, timingSafeEqual } from "node:crypto";
import { base16 } from "multiformats/bases/base16";
import { base58btc as base58btc2 } from "multiformats/bases/base58";
import { base64, base64url } from "multiformats/bases/base64";
import * as Digest from "multiformats/hashes/digest";
var MULTIHASH_ALG = { 18: "sha256", 19: "sha512", 32: "sha384" };
var SRI_ALG = { sha256: "sha256", sha384: "sha384", sha512: "sha512" };
var MULTIBASE = base58btc2.decoder.or(base64.decoder).or(base64url.decoder).or(base16.decoder);
async function resolveBoundPolicy(vc, options) {
  const subject = subjectWithPolicy(vc);
  const policyValue = subject?.[SVC_POLICY];
  if (policyValue === void 0) return { errors: [] };
  if (typeof policyValue === "object" && policyValue !== null) {
    return { policy: { form: "embedded", content: policyValue }, errors: [] };
  }
  if (typeof policyValue !== "string") {
    return { errors: [integrityError("svc:policy is neither an IRI nor an embedded object")] };
  }
  const related = relatedResourceFor(vc, policyValue);
  if (related === void 0 || related.digestSRI === void 0 && related.digestMultibase === void 0) {
    return {
      errors: [
        integrityError(`bare policy reference <${policyValue}> has no relatedResource digest (D4)`)
      ]
    };
  }
  if (options.fetch === void 0) {
    return {
      errors: [integrityError("no fetch injected \u2014 cannot dereference the policy (fail-closed)")]
    };
  }
  let octets;
  let mediaType;
  try {
    const response = await options.fetch(policyValue);
    if (!response.ok) {
      return { errors: [integrityError(`policy HTTP ${response.status}`)] };
    }
    octets = new Uint8Array(await response.arrayBuffer());
    mediaType = related.mediaType ?? response.headers.get("content-type") ?? void 0;
  } catch {
    return { errors: [integrityError("policy retrieval threw")] };
  }
  if (!digestMatches(octets, related)) {
    return {
      errors: [integrityError(`policy octets do not match the signed digest for <${policyValue}>`)]
    };
  }
  return {
    policy: {
      form: "reference",
      iri: policyValue,
      octets,
      ...mediaType !== void 0 ? { mediaType } : {}
    },
    errors: []
  };
}
function subjectWithPolicy(vc) {
  const subjects = Array.isArray(vc.credentialSubject) ? vc.credentialSubject : [vc.credentialSubject];
  return subjects.find((s) => s[SVC_POLICY] !== void 0);
}
function relatedResourceFor(vc, iri) {
  if (vc.relatedResource === void 0) return void 0;
  const resources = Array.isArray(vc.relatedResource) ? vc.relatedResource : [vc.relatedResource];
  return resources.find((r) => r.id === iri);
}
function digestMatches(octets, related) {
  if (related.digestSRI !== void 0 && !sriMatches(octets, related.digestSRI)) return false;
  if (related.digestMultibase !== void 0 && !multibaseMatches(octets, related.digestMultibase)) {
    return false;
  }
  return true;
}
function sriMatches(octets, digestSRI) {
  const dash = digestSRI.indexOf("-");
  if (dash === -1) return false;
  const alg = SRI_ALG[digestSRI.slice(0, dash)];
  if (alg === void 0) return false;
  let expected;
  try {
    expected = Buffer.from(digestSRI.slice(dash + 1), "base64");
  } catch {
    return false;
  }
  const actual = createHash2(alg).update(octets).digest();
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
function multibaseMatches(octets, digestMultibase) {
  let digest;
  try {
    digest = Digest.decode(MULTIBASE.decode(digestMultibase));
  } catch {
    return false;
  }
  const alg = MULTIHASH_ALG[digest.code];
  if (alg === void 0) return false;
  const actual = createHash2(alg).update(octets).digest();
  const expected = Buffer.from(digest.digest);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
function integrityError(message) {
  return { code: "POLICY_INTEGRITY", message };
}

// src/presentation.ts
import { randomUUID as randomUUID3 } from "node:crypto";

// src/status-list.ts
import { gunzipSync } from "node:zlib";
import { base64url as base64url2 } from "multiformats/bases/base64";
var MIN_BITSTRING_ENTRIES = 131072;
async function checkCredentialStatus(params) {
  const errors = [];
  for (const entry of params.entries) {
    errors.push(...await checkOneEntry(entry, params));
  }
  return errors;
}
function monotonicKey(credentialId) {
  return `${credentialId}|revocation`;
}
async function checkOneEntry(entry, params) {
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
  const monoKey = purpose === "revocation" && params.credentialId !== void 0 ? monotonicKey(params.credentialId) : void 0;
  if (monoKey !== void 0 && params.revocationStore !== void 0) {
    let previouslyRevoked;
    try {
      previouslyRevoked = await params.revocationStore.has(monoKey);
    } catch {
      return [retrievalError("revocation store read failed (fail-closed)")];
    }
    if (previouslyRevoked) {
      return [
        { code: "REVOKED", message: `credential ${params.credentialId} was previously revoked` }
      ];
    }
  }
  if (params.fetch === void 0) {
    return [retrievalError("no fetch injected \u2014 cannot retrieve the status list (fail-closed)")];
  }
  const list = await fetchStatusList(entry, purpose, params, params.fetch);
  if ("error" in list) return [list.error];
  const bitSet = bitAt(list.bytes, index);
  if (bitSet === void 0) {
    return [retrievalError(`statusListIndex ${index} is out of range for the bitstring`)];
  }
  if (!bitSet) return [];
  if (purpose === "revocation") {
    if (monoKey !== void 0 && params.revocationStore !== void 0) {
      try {
        await params.revocationStore.add(monoKey);
      } catch {
      }
    }
    return [{ code: "REVOKED", message: `credential is revoked (statusListIndex ${index})` }];
  }
  return [{ code: "SUSPENDED", message: `credential is suspended (statusListIndex ${index})` }];
}
async function fetchStatusList(entry, purpose, params, fetch) {
  let body;
  let contentType2;
  try {
    const response = await fetch(entry.statusListCredential);
    if (!response.ok) {
      return { error: retrievalError(`status list HTTP ${response.status}`) };
    }
    body = await response.text();
    contentType2 = response.headers.get("content-type") ?? "text/turtle";
  } catch {
    return { error: retrievalError("status list retrieval threw") };
  }
  const result = await params.verifyStatusCredential(body, contentType2, {
    resolveKey: params.resolveKey,
    registry: params.registry,
    now: params.now,
    baseIRI: entry.statusListCredential,
    ...params.fetch !== void 0 ? { fetch: params.fetch } : {},
    ...params.isControlledBy !== void 0 ? { isControlledBy: params.isControlledBy } : {},
    // Never recurse into the status-list credential's OWN status (avoids a cycle).
    checkStatus: false
  });
  if (!result.verified) {
    return { error: retrievalError("status list credential failed verification") };
  }
  if (result.issuer !== params.issuer) {
    return {
      error: retrievalError(`status list issuer ${result.issuer} != hop issuer ${params.issuer}`)
    };
  }
  const signed = result.signedDocumentQuads;
  if (signed === void 0) {
    return { error: retrievalError("status list credential exposed no signed quads") };
  }
  const listPurpose = firstSignedLiteral(signed, STATUS_PURPOSE);
  if (listPurpose !== purpose) {
    return {
      error: retrievalError(`status list purpose "${listPurpose}" != entry "${purpose}"`)
    };
  }
  const encoded = firstSignedLiteral(signed, STATUS_ENCODED_LIST);
  if (encoded === void 0) {
    return { error: retrievalError("status list has no encodedList") };
  }
  let bytes;
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
function decodeBitstring(encodedList) {
  const compressed = base64url2.decode(encodedList);
  return new Uint8Array(gunzipSync(compressed));
}
function bitAt(bytes, index) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= bytes.length * 8) {
    return void 0;
  }
  const byteIndex = Math.floor(index / 8);
  const bitInByte = index % 8;
  const byte = bytes[byteIndex];
  return (byte >> 7 - bitInByte & 1) === 1;
}
function firstSignedLiteral(quads, predicate) {
  for (const quad of quads) {
    if (quad.predicate.value === predicate && quad.object.termType === "Literal") {
      return quad.object.value;
    }
  }
  return void 0;
}
function retrievalError(message) {
  return { code: "STATUS_RETRIEVAL_ERROR", message };
}

// src/verify-core.ts
function resolveControlledBy(options, expectedPurpose) {
  if (options.isControlledBy !== void 0) return options.isControlledBy;
  if (options.fetch !== void 0) {
    return documentResolvedControlledBy(options.fetch, expectedPurpose);
  }
  return () => false;
}
function normalizePurpose(purpose) {
  const hash = purpose.lastIndexOf("#");
  return hash === -1 ? purpose : purpose.slice(hash + 1);
}
function checkValidityWindow(now, validFrom, validUntil) {
  const errors = [];
  if (validUntil !== void 0) {
    const until = Date.parse(validUntil);
    if (!Number.isNaN(until) && now.getTime() > until) {
      errors.push({ code: "EXPIRED", message: `credential expired at ${validUntil}` });
    }
  }
  if (validFrom !== void 0) {
    const from = Date.parse(validFrom);
    if (!Number.isNaN(from) && now.getTime() < from) {
      errors.push({ code: "NOT_YET_VALID", message: `credential not valid before ${validFrom}` });
    }
  }
  return errors;
}
async function verifyProofSet(input) {
  const errors = [];
  for (const proof of input.proofs) {
    const suite = input.registry.get(proof.cryptosuite);
    if (suite === void 0) {
      errors.push({
        code: "UNKNOWN_CRYPTOSUITE",
        message: `no registered suite for cryptosuite "${proof.cryptosuite}"`
      });
      continue;
    }
    if (normalizePurpose(proof.proofPurpose) !== normalizePurpose(input.expectedPurpose)) {
      errors.push({
        code: "PROOF_PURPOSE_MISMATCH",
        message: `proofPurpose "${proof.proofPurpose}" != expected "${input.expectedPurpose}"`
      });
    }
    let controlled;
    try {
      controlled = await input.controlledBy(proof.verificationMethod, input.issuer);
    } catch {
      controlled = false;
    }
    if (!controlled) {
      errors.push({
        code: "ISSUER_MISMATCH",
        message: `verificationMethod ${proof.verificationMethod} is not controlled by issuer ${input.issuer}`
      });
    }
    if (!await verifyOneProof(suite, input.documentQuads, proof, input.resolveKey)) {
      errors.push({
        code: "INVALID_SIGNATURE",
        message: `signature did not verify for proof (${proof.cryptosuite})`
      });
    }
  }
  return errors;
}
async function verifyOneProof(suite, documentQuads, proof, resolveKey) {
  try {
    return await suite.verify(documentQuads, proof, { resolveKey });
  } catch {
    return false;
  }
}

// src/verify-rdf.ts
async function parseAndVerifyCredential(body, contentType2, options) {
  let dataset;
  try {
    dataset = await parseRdf(body, contentType2, {
      ...options.baseIRI !== void 0 ? { baseIRI: options.baseIRI } : {}
    });
  } catch {
    return {
      verified: false,
      errors: [{ code: "MALFORMED", message: "credential did not parse" }]
    };
  }
  const credentials = wrapVc(dataset).credentials();
  if (credentials.length !== 1) {
    return {
      verified: false,
      errors: [
        {
          code: "MALFORMED",
          message: `expected exactly one credential node, found ${credentials.length}`
        }
      ],
      dataset
    };
  }
  const node = credentials[0];
  const issuer = firstIri(node.issuers);
  if (issuer === void 0) {
    return {
      verified: false,
      errors: [{ code: "MALFORMED", message: "credential has no issuer IRI" }],
      dataset,
      credentialId: node.value
    };
  }
  const now = options.now ?? /* @__PURE__ */ new Date();
  const registry = options.registry ?? defaultSuiteRegistry();
  const expectedPurpose = options.expectedProofPurpose ?? "assertionMethod";
  const controlledBy = resolveControlledBy(options, expectedPurpose);
  const errors = [];
  errors.push(
    ...checkValidityWindow(now, firstLiteral(node.validFroms), firstLiteral(node.validUntils))
  );
  if (options.trustedIssuers !== void 0 && !options.trustedIssuers.includes(issuer)) {
    errors.push({ code: "UNTRUSTED_ISSUER", message: `issuer ${issuer} is not trusted` });
  }
  const proofNodes = [...node.proofs];
  if (proofNodes.length === 0) {
    errors.push({ code: "NO_PROOF", message: "credential carries no proof" });
  }
  const proofs = [];
  for (const proofNode of proofNodes) {
    const parsed = readProof(proofNode);
    if (parsed === void 0) {
      errors.push({
        code: "INVALID_SIGNATURE",
        message: "malformed proof node (missing cryptosuite/method/purpose/proofValue)"
      });
    } else {
      proofs.push(parsed);
    }
  }
  const documentQuads = documentQuadsWithoutProofs(dataset, proofNodes);
  errors.push(
    ...await verifyProofSet({
      documentQuads,
      proofs,
      issuer,
      registry,
      controlledBy,
      expectedPurpose,
      resolveKey: options.resolveKey
    })
  );
  if (options.checkStatus !== false && errors.length === 0) {
    const entries = readStatusEntries(dataset, node.value);
    if (entries.length > 0) {
      errors.push(
        ...await checkCredentialStatus({
          entries,
          credentialId: node.value,
          issuer,
          now,
          fetch: options.fetch,
          revocationStore: options.revocationStore,
          registry,
          resolveKey: options.resolveKey,
          isControlledBy: options.isControlledBy,
          verifyStatusCredential: parseAndVerifyCredential
        })
      );
    }
  }
  return errors.length === 0 ? {
    verified: true,
    errors: [],
    issuer,
    dataset,
    signedDocumentQuads: documentQuads,
    credentialId: node.value
  } : {
    verified: false,
    errors,
    issuer,
    dataset,
    signedDocumentQuads: documentQuads,
    credentialId: node.value
  };
}
function readStatusEntries(dataset, credentialId) {
  const entries = [];
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
      ...link.object.termType === "NamedNode" ? { id: entryId } : {},
      type,
      statusPurpose,
      statusListIndex,
      statusListCredential
    });
  }
  return entries;
}
function readProof(proof) {
  const cryptosuite = firstLiteral(proof.cryptosuites);
  const verificationMethod = firstIri(proof.verificationMethods);
  const proofValue = firstLiteral(proof.proofValues);
  const proofPurpose = firstIri(proof.proofPurposes);
  if (cryptosuite === void 0 || verificationMethod === void 0 || proofValue === void 0 || proofPurpose === void 0) {
    return void 0;
  }
  const created = firstLiteral(proof.createds);
  return {
    type: "DataIntegrityProof",
    cryptosuite,
    verificationMethod,
    proofPurpose,
    proofValue,
    ...created !== void 0 ? { created } : {}
  };
}
function documentQuadsWithoutProofs(dataset, proofNodes) {
  const proofIds = new Set(proofNodes.map((p) => p.value));
  const out = [];
  for (const quad of dataset.match()) {
    if (quad.predicate.value === SEC_PROOF) continue;
    if (proofIds.has(quad.subject.value)) continue;
    out.push(quad);
  }
  return out;
}

// src/verify.ts
function proofsOf(vc) {
  const proof = vc.proof;
  return Array.isArray(proof) ? [...proof] : [proof];
}
function unsigned(vc) {
  const { proof: _proof, ...rest } = vc;
  return rest;
}
function statusEntriesOf(vc) {
  const cs = vc.credentialStatus;
  if (cs === void 0) return [];
  return Array.isArray(cs) ? [...cs] : [cs];
}
async function verifyCredential(vc, options) {
  const errors = [];
  const registry = options.registry ?? defaultSuiteRegistry();
  const now = options.now ?? /* @__PURE__ */ new Date();
  const expectedPurpose = options.expectedProofPurpose ?? "assertionMethod";
  const controlledBy = resolveControlledBy(options, expectedPurpose);
  if (vc === null || typeof vc !== "object" || typeof vc.issuer !== "string" || vc.issuer.length === 0 || vc.credentialSubject === void 0) {
    return {
      verified: false,
      errors: [{ code: "MALFORMED", message: "not a well-formed credential" }]
    };
  }
  const issuer = vc.issuer;
  const proofs = vc.proof === void 0 ? [] : proofsOf(vc);
  if (proofs.length === 0) {
    errors.push({ code: "NO_PROOF", message: "credential carries no proof" });
  }
  errors.push(...checkValidityWindow(now, vc.validFrom, vc.validUntil));
  if (options.trustedIssuers !== void 0 && !options.trustedIssuers.includes(issuer)) {
    errors.push({ code: "UNTRUSTED_ISSUER", message: `issuer ${issuer} is not trusted` });
  }
  errors.push(
    ...await verifyProofSet({
      documentQuads: credentialToRdf(unsigned(vc)),
      proofs,
      issuer,
      registry,
      controlledBy,
      expectedPurpose,
      resolveKey: options.resolveKey
    })
  );
  const statusEntries = statusEntriesOf(vc);
  if (statusEntries.length > 0 && options.checkStatus !== false && errors.length === 0) {
    errors.push(
      ...await checkCredentialStatus({
        entries: statusEntries,
        credentialId: typeof vc.id === "string" ? vc.id : void 0,
        issuer,
        now,
        fetch: options.fetch,
        revocationStore: options.revocationStore,
        registry,
        resolveKey: options.resolveKey,
        isControlledBy: options.isControlledBy,
        verifyStatusCredential: parseAndVerifyCredential
      })
    );
  }
  return errors.length === 0 ? { verified: true, errors: [], issuer } : { verified: false, errors, issuer };
}

// src/presentation.ts
function presentationToRdf(presentation) {
  const id = presentation.id ?? `urn:uuid:${randomUUID3()}`;
  const subject = iriRef(id);
  const b = new GraphBuilder();
  b.addType(subject, VC_PRESENTATION);
  if (presentation.holder !== void 0) {
    b.addIri(subject, VC_HOLDER, presentation.holder);
  }
  for (const vc of presentation.verifiableCredential) {
    if (typeof vc.id === "string" && vc.id.length > 0) {
      b.addIri(subject, VC_VERIFIABLE_CREDENTIAL, vc.id);
    }
  }
  return b.quads();
}
async function signPresentation(presentation, key, options = {}) {
  const suite = options.suite ?? new DataIntegritySuite("eddsa-rdfc-2022");
  const id = presentation.id ?? `urn:uuid:${randomUUID3()}`;
  const withId = { ...presentation, id };
  const proof = await suite.sign(presentationToRdf(withId), {
    key,
    proofPurpose: options.proofPurpose ?? "authentication",
    created: options.created ?? /* @__PURE__ */ new Date(),
    ...options.challenge !== void 0 ? { challenge: options.challenge } : {},
    ...options.domain !== void 0 ? { domain: options.domain } : {}
  });
  return { ...withId, proof };
}
function proofsOf2(vp) {
  const proof = vp.proof;
  return Array.isArray(proof) ? [...proof] : [proof];
}
async function verifyPresentation(vp, options) {
  if (vp === null || typeof vp !== "object" || !Array.isArray(vp.verifiableCredential) || vp.proof === void 0) {
    return {
      verified: false,
      errors: [{ code: "MALFORMED", message: "not a well-formed presentation" }],
      credentialResults: []
    };
  }
  const errors = [];
  const credentialResults = [];
  for (const vc of vp.verifiableCredential) {
    const result = await verifyCredential(vc, options);
    credentialResults.push(result);
    if (!result.verified) {
      errors.push(...result.errors);
    }
  }
  const holder = vp.holder;
  if (typeof holder !== "string" || holder.length === 0) {
    errors.push({ code: "HOLDER_UNVERIFIED", message: "presentation has no holder to bind" });
    return { verified: false, errors, credentialResults };
  }
  const proofs = proofsOf2(vp);
  if (proofs.length === 0) {
    errors.push({ code: "NO_PROOF", message: "presentation carries no proof" });
  }
  for (const proof of proofs) {
    if (options.challenge !== void 0 && proof.challenge !== options.challenge) {
      errors.push({
        code: "CHALLENGE_MISMATCH",
        message: `proof.challenge "${proof.challenge}" != expected "${options.challenge}"`
      });
    }
    if (options.domain !== void 0 && proof.domain !== options.domain) {
      errors.push({
        code: "DOMAIN_MISMATCH",
        message: `proof.domain "${proof.domain}" != expected "${options.domain}"`
      });
    }
  }
  const registry = options.registry ?? defaultSuiteRegistry();
  const controlledBy = resolveControlledBy(options, "authentication");
  errors.push(
    ...await verifyProofSet({
      documentQuads: presentationToRdf(unsignedPresentation(vp)),
      proofs,
      issuer: holder,
      registry,
      controlledBy,
      expectedPurpose: "authentication",
      resolveKey: options.resolveKey
    })
  );
  for (const vc of vp.verifiableCredential) {
    if (!credentialNamesHolder(vc, holder)) {
      errors.push({
        code: "HOLDER_UNVERIFIED",
        message: `holder ${holder} is neither the subject nor the authorized agent of a presented credential`
      });
    }
  }
  return errors.length === 0 ? { verified: true, errors: [], holder, credentialResults } : { verified: false, errors, holder, credentialResults };
}
function unsignedPresentation(vp) {
  const { proof: _proof, ...rest } = vp;
  return rest;
}
function credentialNamesHolder(vc, holder) {
  const subjects = Array.isArray(vc.credentialSubject) ? vc.credentialSubject : [vc.credentialSubject];
  for (const subject of subjects) {
    if (subject.id === holder) return true;
    const authorizes = subject[SVC_AUTHORIZES];
    if (typeof authorizes === "string" && authorizes === holder) return true;
  }
  return false;
}
export {
  CredentialNode,
  DataIntegritySuite,
  PresentationNode,
  ProofNode,
  SVC,
  SVC_AGENT_AUTHORIZATION,
  SuiteRegistry,
  VC,
  VC_V2_CONTEXT,
  VcDataset,
  agentAuthorizationFromRdf,
  base58btcDecode,
  base58btcEncode,
  buildAgentAuthorizationCredential,
  canonicalNQuads,
  credentialFromRdf,
  credentialMetaFromNode,
  credentialToJsonLd,
  credentialToRdf,
  credentialToTurtle,
  cryptosuiteForKeyType,
  dataIntegrityHash,
  defaultSuiteRegistry,
  documentResolvedControlledBy,
  exportPrivateJwk,
  exportPublicJwk,
  generateKeyPairForSuite,
  importKeyPair,
  importPublicKey,
  issue,
  issueAgentAuthorization,
  parseAndVerifyCredential,
  parseCredentialRdf,
  prefixControlledBy,
  presentationToRdf,
  proofOptionsQuads,
  resolveBoundPolicy,
  serialize2 as serialize,
  signPresentation,
  signedCredentialToRdf,
  signedCredentialToTurtle,
  verifyCredential,
  verifyPresentation,
  wrapVc
};
//# sourceMappingURL=index.js.map
