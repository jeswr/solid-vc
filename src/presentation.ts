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
import { SVC_AUTHORIZES, VC_HOLDER, VC_PRESENTATION, VC_VERIFIABLE_CREDENTIAL } from "./vocab.js";
import { GraphBuilder, iriRef } from "./wrappers.js";

/**
 * Lower a {@link Presentation} (UNSIGNED — no proof) to RDF quads: the presentation
 * node (`VerifiablePresentation`), its `holder`, and a `verifiableCredential` link to
 * each presented credential's IRI. The presentation proof is computed over these
 * quads, so the holder + the set of presented credential IRIs are under the signature.
 */
export function presentationToRdf(presentation: Presentation): Quad[] {
  const id = presentation.id ?? `urn:uuid:${randomUUID()}`;
  const subject = iriRef(id);
  const b = new GraphBuilder();
  b.addType(subject, VC_PRESENTATION);
  if (presentation.holder !== undefined) {
    b.addIri(subject, VC_HOLDER, presentation.holder);
  }
  for (const vc of presentation.verifiableCredential) {
    if (typeof vc.id === "string" && vc.id.length > 0) {
      b.addIri(subject, VC_VERIFIABLE_CREDENTIAL, vc.id);
    }
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
  const proof = await suite.sign(presentationToRdf(withId), {
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

/** Normalise one-or-many proofs to an array. */
function proofsOf(vp: VerifiablePresentation): DataIntegrityProof[] {
  const proof = vp.proof;
  return Array.isArray(proof)
    ? [...(proof as readonly DataIntegrityProof[])]
    : [proof as DataIntegrityProof];
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
      documentQuads: presentationToRdf(unsignedPresentation(vp)),
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

/** Whether `holder` is the subject id or the `svc:authorizes` agent of the credential. */
function credentialNamesHolder(vc: VerifiableCredential, holder: string): boolean {
  const subjects = Array.isArray(vc.credentialSubject)
    ? vc.credentialSubject
    : [vc.credentialSubject];
  for (const subject of subjects) {
    if (subject.id === holder) return true;
    const authorizes = subject[SVC_AUTHORIZES];
    if (typeof authorizes === "string" && authorizes === holder) return true;
  }
  return false;
}
