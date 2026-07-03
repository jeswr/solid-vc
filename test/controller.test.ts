// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The document-resolved issuer–key controller check (this note's §"Issuer–key
// binding"; DECISIONS.md D11). Exhaustive accept/reject matrix: the safe default
// resolves the issuer's OWN authoritative document and confirms it lists the
// verification method — and fails CLOSED on every error (bad IRI, non-2xx, fetch/
// parse throw, missing relationship, or a sibling-tenant document that tries to
// vouch for someone else's key). The unsafe prefix heuristic is an explicit opt-in.

import { describe, expect, it } from "vitest";
import { documentResolvedControlledBy, prefixControlledBy } from "../src/controller.js";
import type { FetchPort, HttpResponse } from "../src/fetch-port.js";
import { issueAgentAuthorization } from "../src/issue.js";
import { verifyCredential } from "../src/verify.js";
import { ACL_READ, AGENT, ISSUER, issuerKey, keyResolver } from "./helpers.js";

const DOC_URL = "https://alice.example/profile";
const VM = `${ISSUER}#key-1`;
const AUTH = { principal: ISSUER, agent: AGENT, action: ACL_READ } as const;

/** A tiny fetch fixture: map a document URL to a Turtle body (or an error/handler). */
function fakeFetch(routes: Record<string, string | { status: number } | (() => never)>): FetchPort {
  return async (url: string): Promise<HttpResponse> => {
    const route = routes[url];
    if (route === undefined) return response("", 404);
    if (typeof route === "function") route(); // throws
    if (typeof route === "object") return response("", route.status);
    return response(route, 200, "text/turtle");
  };
}

function response(body: string, status: number, contentType = "text/turtle"): HttpResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (n: string) => (n.toLowerCase() === "content-type" ? contentType : null) },
    text: async () => body,
    arrayBuffer: async () => new TextEncoder().encode(body).buffer as ArrayBuffer,
  };
}

const ASSERTION = "https://w3id.org/security#assertionMethod";
const AUTHENTICATION = "https://w3id.org/security#authentication";

describe("documentResolvedControlledBy — unit accept/reject matrix", () => {
  it("accepts when the issuer's own document asserts sec:assertionMethod → vm", async () => {
    const doc = `<${ISSUER}> <${ASSERTION}> <${VM}> .`;
    const check = documentResolvedControlledBy(fakeFetch({ [DOC_URL]: doc }));
    expect(await check(VM, ISSUER)).toBe(true);
  });

  it("accepts a WebID profile that uses RELATIVE IRIs (`<#me>` / `<#key-1>`)", async () => {
    // A real Solid WebID document typically writes the WebID as `<#me>` relative to
    // the document URL. The parse must be based on the document URL so those resolve
    // to the absolute issuer / verification-method strings; otherwise the fail-closed
    // default would wrongly reject a valid profile. (roborev c504cbb Medium.)
    const relDoc = "https://rel.example/card";
    const relIssuer = `${relDoc}#me`;
    const relVm = `${relDoc}#key-1`;
    const doc = `<#me> <${ASSERTION}> <#key-1> .`;
    const check = documentResolvedControlledBy(fakeFetch({ [relDoc]: doc }));
    expect(await check(relVm, relIssuer)).toBe(true);
  });

  it("is PURPOSE-AWARE: a key listed only for assertionMethod fails an authentication check", async () => {
    // roborev Medium: the relationship must match the expected proof purpose.
    const doc = `<${ISSUER}> <${ASSERTION}> <${VM}> .`;
    const asAssertion = documentResolvedControlledBy(fakeFetch({ [DOC_URL]: doc }));
    const asAuthentication = documentResolvedControlledBy(
      fakeFetch({ [DOC_URL]: doc }),
      "authentication",
    );
    expect(await asAssertion(VM, ISSUER)).toBe(true);
    expect(await asAuthentication(VM, ISSUER)).toBe(false);
  });

  it("accepts an authentication key when the document lists it under sec:authentication", async () => {
    const doc = `<${ISSUER}> <${AUTHENTICATION}> <${VM}> .`;
    const check = documentResolvedControlledBy(fakeFetch({ [DOC_URL]: doc }), "authentication");
    expect(await check(VM, ISSUER)).toBe(true);
  });

  it("REJECTS when the document does not list the key at all", async () => {
    const doc = `<${ISSUER}> <http://xmlns.com/foaf/0.1/name> "Alice" .`;
    const check = documentResolvedControlledBy(fakeFetch({ [DOC_URL]: doc }));
    expect(await check(VM, ISSUER)).toBe(false);
  });

  it("REJECTS a same-origin sibling that claims control of the issuer's key", async () => {
    // The issuer's OWN doc is authoritative; a statement about a DIFFERENT subject
    // (alice-evil) in that same document must not vouch for the issuer's key.
    const evil = "https://alice.example/profile#evil";
    const doc = `<${evil}> <${ASSERTION}> <${VM}> .`;
    const check = documentResolvedControlledBy(fakeFetch({ [DOC_URL]: doc }));
    expect(await check(VM, ISSUER)).toBe(false);
  });

  it("REJECTS (fail-closed) on a non-2xx issuer document", async () => {
    const check = documentResolvedControlledBy(fakeFetch({ [DOC_URL]: { status: 500 } }));
    expect(await check(VM, ISSUER)).toBe(false);
  });

  it("REJECTS (fail-closed) when the fetch throws", async () => {
    const check = documentResolvedControlledBy(
      fakeFetch({
        [DOC_URL]: () => {
          throw new Error("network down");
        },
      }),
    );
    expect(await check(VM, ISSUER)).toBe(false);
  });

  it("REJECTS a non-http issuer or verification method (did:, urn:)", async () => {
    const check = documentResolvedControlledBy(fakeFetch({}));
    expect(await check("did:key:zABC#zABC", ISSUER)).toBe(false);
    expect(await check(VM, "did:web:alice.example")).toBe(false);
  });
});

describe("verifyCredential — controller default is document-resolved / fail-closed", () => {
  it("verifies end-to-end when the issuer document lists the signing key", async () => {
    const key = await issuerKey("Ed25519");
    const vc = await issueAgentAuthorization(AUTH, key);
    const doc = `<${ISSUER}> <${ASSERTION}> <${VM}> .`;
    const result = await verifyCredential(vc, {
      resolveKey: keyResolver(key),
      fetch: fakeFetch({ [DOC_URL]: doc }),
    });
    expect(result.verified).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("rejects with ISSUER_MISMATCH when the issuer document omits the key", async () => {
    const key = await issuerKey("Ed25519");
    const vc = await issueAgentAuthorization(AUTH, key);
    const doc = `<${ISSUER}> <http://xmlns.com/foaf/0.1/name> "Alice" .`;
    const result = await verifyCredential(vc, {
      resolveKey: keyResolver(key),
      fetch: fakeFetch({ [DOC_URL]: doc }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("ISSUER_MISMATCH");
  });

  it("FAILS CLOSED (ISSUER_MISMATCH) when neither fetch nor isControlledBy is given", async () => {
    const key = await issuerKey("Ed25519");
    const vc = await issueAgentAuthorization(AUTH, key);
    const result = await verifyCredential(vc, { resolveKey: keyResolver(key) });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("ISSUER_MISMATCH");
  });

  it("still accepts the explicit (unsafe) prefix opt-in", async () => {
    const key = await issuerKey("Ed25519");
    const vc = await issueAgentAuthorization(AUTH, key);
    const result = await verifyCredential(vc, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
    });
    expect(result.verified).toBe(true);
  });
});
