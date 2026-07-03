// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Verifiable Presentations with CHALLENGE + DOMAIN binding and HOLDER binding — this
// note's §"Presenting a chain". Holding a credential is NOT authority; being the party
// it names, and proving it, is. So a presentation is accepted only when:
//
//   1. every embedded credential independently verifies (its own gates);
//   2. the presentation's OWN proof verifies — `proofPurpose = authentication`, signed
//      by a key the `holder` controls (document-resolved), binding the verifier's
//      `challenge` + `domain` (anti-replay; both under the signature);
//   3. HOLDER BINDING: the `holder` is the party each presented credential is about —
//      its `credentialSubject.id` OR (for an agent-authorization credential) its
//      `svc:authorizes` agent. This is what proves control of the credential's subject,
//      not mere possession of the VC.
//
// Fail-closed throughout — a missing holder, a challenge/domain mismatch, an
// unverified embedded credential, or an unproven holder all deny.

import { randomUUID } from "node:crypto";
import type { Quad } from "@rdfjs/types";
import { base58btc } from "multiformats/bases/base58";
import { sha256 } from "multiformats/hashes/sha2";
import { canonicalNQuads } from "./canonicalize.js";
import { signedCredentialToRdf } from "./credential.js";
import { DataIntegritySuite, defaultSuiteRegistry, type ProofSuite } from "./proof.js";
import type {
  DataIntegrityProof,
  IssueOptions,
  KeyPair,
  Presentation,
  VerifiableCredential,
  VerifiablePresentation,
  VerificationError,
  VerificationResult,
} from "./types.js";
import type { VerifyCredentialOptions } from "./verify.js";
import { verifyCredential } from "./verify.js";
import { resolveControlledBy, verifyProofSet } from "./verify-core.js";
import {
  SEC_DIGEST_MULTIBASE,
  SVC_AGENT_AUTHORIZATION,
  SVC_AUTHORIZES,
  VC_HOLDER,
  VC_PRESENTATION,
  VC_VERIFIABLE_CREDENTIAL,
} from "./vocab.js";
import { GraphBuilder, iriRef, type NodeRef } from "./wrappers.js";

/** A content digest of a SIGNED credential (its canonical form) — multibase multihash. */
async function credentialDigest(vc: VerifiableCredential): Promise<string> {
  const canon = await canonicalNQuads(signedCredentialToRdf(vc));
  const mh = await sha256.digest(new TextEncoder().encode(canon));
  return base58btc.encode(mh.bytes);
}

/**
 * Lower a {@link Presentation} (UNSIGNED — no proof) to RDF quads: the presentation
 * node (`VerifiablePresentation`), its `holder`, and — per presented credential — a
 * `verifiableCredential` link PLUS a `sec:digestMultibase` of the credential's SIGNED
 * canonical form. Binding the digest (not merely the credential `id`) is what stops a
 * same-`id` credential from being SUBSTITUTED without breaking the presentation
 * signature. Async because the digest canonicalizes each credential. The presentation
 * proof is computed over these quads.
 */
export async function presentationToRdf(presentation: Presentation): Promise<Quad[]> {
  const id = presentation.id ?? `urn:uuid:${randomUUID()}`;
  const subject = iriRef(id);
  const b = new GraphBuilder();
  b.addType(subject, VC_PRESENTATION);
  if (presentation.holder !== undefined) {
    b.addIri(subject, VC_HOLDER, presentation.holder);
  }
  for (const vc of presentation.verifiableCredential) {
    // Skip a malformed entry (e.g. `verifiableCredential: [null]`) — it is reported
    // separately by the per-credential verify + holder binding; lowering it must not
    // throw here.
    if (vc === null || typeof vc !== "object") continue;
    const node: NodeRef =
      typeof vc.id === "string" && vc.id.length > 0
        ? iriRef(vc.id)
        : b.linkBlankNode(subject, VC_VERIFIABLE_CREDENTIAL);
    if (node.kind === "iri") {
      b.addIri(subject, VC_VERIFIABLE_CREDENTIAL, node.value);
    }
    b.addLiteral(node, SEC_DIGEST_MULTIBASE, await credentialDigest(vc));
  }
  return b.quads();
}

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
export async function signPresentation(
  presentation: Presentation,
  key: KeyPair | unknown,
  options: SignPresentationOptions = {},
): Promise<VerifiablePresentation> {
  const suite = options.suite ?? new DataIntegritySuite("eddsa-rdfc-2022");
  const id = presentation.id ?? `urn:uuid:${randomUUID()}`;
  const withId: Presentation = { ...presentation, id };
  const proof = await suite.sign(await presentationToRdf(withId), {
    key,
    proofPurpose: options.proofPurpose ?? "authentication",
    created: options.created ?? new Date(),
    ...(options.challenge !== undefined ? { challenge: options.challenge } : {}),
    ...(options.domain !== undefined ? { domain: options.domain } : {}),
  });
  return { ...withId, proof };
}

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

/** Normalise one-or-many proofs to an array of ONLY well-formed proof objects. */
function proofsOf(vp: VerifiablePresentation): DataIntegrityProof[] {
  const proof = vp.proof;
  const raw: unknown[] = Array.isArray(proof) ? [...proof] : [proof];
  return raw.filter((p): p is DataIntegrityProof => p !== null && typeof p === "object");
}

/**
 * Verify a {@link VerifiablePresentation}: every embedded credential, the presentation
 * proof (authentication purpose, holder-controlled key, challenge + domain), and holder
 * binding. Never throws; fail-closed.
 */
export async function verifyPresentation(
  vp: VerifiablePresentation,
  options: VerifyPresentationOptions,
): Promise<PresentationVerificationResult> {
  // 1. structural
  if (
    vp === null ||
    typeof vp !== "object" ||
    !Array.isArray(vp.verifiableCredential) ||
    vp.proof === undefined
  ) {
    return {
      verified: false,
      errors: [{ code: "MALFORMED", message: "not a well-formed presentation" }],
      credentialResults: [],
    };
  }

  const errors: VerificationError[] = [];

  // 2. every embedded credential must independently verify.
  const credentialResults: VerificationResult[] = [];
  for (const vc of vp.verifiableCredential) {
    const result = await verifyCredential(vc, options);
    credentialResults.push(result);
    if (!result.verified) {
      errors.push(...result.errors);
    }
  }

  // 3. the holder must be present (there is nothing to bind without it).
  const holder = vp.holder;
  if (typeof holder !== "string" || holder.length === 0) {
    errors.push({ code: "HOLDER_UNVERIFIED", message: "presentation has no holder to bind" });
    return { verified: false, errors, credentialResults };
  }

  // 4. the presentation proof: authentication purpose, holder-controlled key,
  //    challenge + domain binding, signature over the presentation graph.
  const proofs = proofsOf(vp);
  if (proofs.length === 0) {
    errors.push({ code: "NO_PROOF", message: "presentation carries no proof" });
  }
  for (const proof of proofs) {
    if (options.challenge !== undefined && proof.challenge !== options.challenge) {
      errors.push({
        code: "CHALLENGE_MISMATCH",
        message: `proof.challenge "${proof.challenge}" != expected "${options.challenge}"`,
      });
    }
    if (options.domain !== undefined && proof.domain !== options.domain) {
      errors.push({
        code: "DOMAIN_MISMATCH",
        message: `proof.domain "${proof.domain}" != expected "${options.domain}"`,
      });
    }
  }
  const registry = options.registry ?? defaultSuiteRegistry();
  const controlledBy = resolveControlledBy(options, "authentication");
  errors.push(
    ...(await verifyProofSet({
      documentQuads: await presentationToRdf(unsignedPresentation(vp)),
      proofs,
      issuer: holder,
      registry,
      controlledBy,
      expectedPurpose: "authentication",
      resolveKey: options.resolveKey,
    })),
  );

  // 5. HOLDER BINDING: the holder must be the party each presented credential names —
  //    its credentialSubject.id, or its svc:authorizes agent (an agent-authz hop).
  for (const vc of vp.verifiableCredential) {
    if (!credentialNamesHolder(vc, holder)) {
      errors.push({
        code: "HOLDER_UNVERIFIED",
        message: `holder ${holder} is neither the subject nor the authorized agent of a presented credential`,
      });
    }
  }

  return errors.length === 0
    ? { verified: true, errors: [], holder, credentialResults }
    : { verified: false, errors, holder, credentialResults };
}

/** Strip the proof to recover the presentation graph the signature covered. */
function unsignedPresentation(vp: VerifiablePresentation): Presentation {
  const { proof: _proof, ...rest } = vp;
  return rest as Presentation;
}

/** Whether `vc`'s declared type includes `AgentAuthorizationCredential`. */
function isAgentAuthorization(vc: VerifiableCredential): boolean {
  const types = vc.type ?? [];
  return types.some((t) => t === "AgentAuthorizationCredential" || t === SVC_AGENT_AUTHORIZATION);
}

/**
 * Whether `holder` is the party the credential NAMES: its `credentialSubject.id`
 * always; its `svc:authorizes` agent ONLY when the credential is an
 * `AgentAuthorizationCredential` (so an unrelated credential that merely happens to
 * carry an `svc:authorizes` claim is not mistaken for a delegation to the holder).
 * Runtime-guarded so a malformed credential entry returns `false`, never throws.
 */
function credentialNamesHolder(vc: VerifiableCredential, holder: string): boolean {
  if (vc === null || typeof vc !== "object" || vc.credentialSubject === undefined) return false;
  const subjects = Array.isArray(vc.credentialSubject)
    ? vc.credentialSubject
    : [vc.credentialSubject];
  const agentAuthz = isAgentAuthorization(vc);
  for (const subject of subjects) {
    if (subject === null || typeof subject !== "object") continue;
    if (subject.id === holder) return true;
    if (agentAuthz) {
      const authorizes = subject[SVC_AUTHORIZES];
      if (typeof authorizes === "string" && authorizes === holder) return true;
    }
  }
  return false;
}
