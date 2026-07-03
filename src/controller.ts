// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The issuer–key CONTROLLER binding check (verifyCredential gate 5). This is a
// TRUST decision, not a string comparison.
//
// THE VULNERABILITY the document-resolving default closes (this note's §"Issuer–key
// binding"; DECISIONS.md D11): the shipped {@link prefixControlledBy} heuristic
// ("the verification method IRI starts with the issuer IRI") is UNSAFE across origin
// and path boundaries — `https://host/alice#key` vs another tenant's document at
// `https://host/alice-evil`, or an attacker-writable path under the same origin.
// A conforming verifier MUST instead resolve the verification method within a
// document the issuer identifier actually controls (VC Data Integrity's
// controller-document model): fetch the issuer's OWN authoritative document and
// confirm it lists the method under a verification relationship.
//
// We only ever read assertions from the ISSUER's own document (the issuer IRI with
// its fragment stripped), fetched through the injected SSRF-guarded {@link FetchPort}
// — never from the verification method's document if that differs, and never from a
// third party. So a sibling tenant's document can never vouch for the issuer's key.
// Everything fails CLOSED: a bad IRI, a non-2xx, a fetch/parse throw, or a missing
// relationship → `false` (→ `ISSUER_MISMATCH`), never a silent accept.

import { parseRdf } from "@jeswr/fetch-rdf";
import type { DatasetCore } from "@rdfjs/types";
import type { FetchPort } from "./fetch-port.js";
import { SEC } from "./vocab.js";

/** An async controller-binding check: is `verificationMethod` controlled by `issuer`? */
export type ControlledByCheck = (
  verificationMethod: string,
  issuer: string,
) => boolean | Promise<boolean>;

/** Whether a string is an absolute http(s) IRI (the only schemes we dereference). */
function isHttpIri(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

/** The document URL for an IRI: the IRI with any `#fragment` removed. */
function documentUrl(iri: string): string {
  const url = new URL(iri);
  url.hash = "";
  return url.toString();
}

/**
 * The controller-document verification-RELATIONSHIP IRI for a proof purpose. A bare
 * token (`assertionMethod`, `authentication`, …) homes under the security vocab
 * (`sec:assertionMethod` — the DID-core verification relationships all live there);
 * an already-absolute IRI is kept verbatim. The controller check requires this exact
 * relationship, so a key listed only for `assertionMethod` does NOT satisfy an
 * `authentication` verify and vice-versa.
 */
function relationshipIriForPurpose(purpose: string): string {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(purpose) ? purpose : `${SEC}${purpose}`;
}

/**
 * The UNSAFE string-prefix heuristic, kept as an EXPLICIT, named opt-in (never the
 * default). The method IRI must equal the issuer IRI or start with `<issuer>#` /
 * `<issuer>/`. Documented unsafe (see the file header); use only in tests or a
 * closed deployment where every WebID is single-tenant and same-origin. A conforming
 * chain verifier MUST override this with {@link documentResolvedControlledBy}.
 */
export function prefixControlledBy(verificationMethod: string, issuer: string): boolean {
  if (verificationMethod === issuer) return true;
  return verificationMethod.startsWith(`${issuer}#`) || verificationMethod.startsWith(`${issuer}/`);
}

/**
 * Build the DOCUMENT-RESOLVED controller check — the safe default. It fetches the
 * issuer's own authoritative document through the injected SSRF-guarded `fetch` and
 * accepts the binding IFF that document asserts
 * `<issuer> <relationship> <verificationMethod>`, where `relationship` is the
 * verification relationship matching the EXPECTED proof purpose (default
 * `sec:assertionMethod`). A key listed only for `assertionMethod` therefore does NOT
 * satisfy an `authentication` verify — the purpose is part of the trust decision, not
 * just the key's controller.
 *
 * The statement is made BY the issuer's own document about the issuer's own key, so a
 * same-origin sibling tenant cannot forge it. Fail-closed on every error.
 *
 * @param fetch - the injected SSRF-guarded fetch port.
 * @param expectedProofPurpose - the proof purpose the key must be authorized for
 *   (default `assertionMethod`). {@link verifyCredential} passes its own
 *   `expectedProofPurpose` so the two gates agree.
 */
export function documentResolvedControlledBy(
  fetch: FetchPort,
  expectedProofPurpose = "assertionMethod",
): ControlledByCheck {
  const relationship = relationshipIriForPurpose(expectedProofPurpose);
  return async (verificationMethod: string, issuer: string): Promise<boolean> => {
    if (!isHttpIri(verificationMethod) || !isHttpIri(issuer)) return false;
    let dataset: DatasetCore;
    try {
      const docUrl = documentUrl(issuer);
      const response = await fetch(docUrl);
      if (!response.ok) return false;
      const body = await response.text();
      const contentType = response.headers.get("content-type") ?? "text/turtle";
      // Base the parse on the document URL so a WebID profile's relative IRIs
      // (`<#me>`, `<#key-1>`) resolve to the absolute issuer / verification-method
      // strings being compared — otherwise a valid relative-IRI profile would be
      // wrongly rejected by the fail-closed default.
      dataset = (await parseRdf(body, contentType, {
        baseIRI: docUrl,
      })) as unknown as DatasetCore;
    } catch {
      return false; // fetch / parse failure → cannot resolve control → deny.
    }
    return documentAssertsRelationship(dataset, issuer, relationship, verificationMethod);
  };
}

/** Whether `dataset` asserts `<issuer> <relationship> <verificationMethod>`. */
function documentAssertsRelationship(
  dataset: DatasetCore,
  issuer: string,
  relationship: string,
  verificationMethod: string,
): boolean {
  for (const quad of dataset.match()) {
    if (
      quad.subject.termType === "NamedNode" &&
      quad.object.termType === "NamedNode" &&
      quad.predicate.value === relationship &&
      quad.subject.value === issuer &&
      quad.object.value === verificationMethod
    ) {
      return true;
    }
  }
  return false;
}
