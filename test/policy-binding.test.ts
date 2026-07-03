// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Policy-CONTENT binding (this note's D4). The `svc:policy` an agent-authz credential
// carries must be bound by CONTENT: EMBEDDED (accepted) or BY-REFERENCE-WITH-DIGEST
// (fetched octets verified against the signed digest). A BARE IRI reference — the
// form the builder used to emit — must be REJECTED with POLICY_INTEGRITY.

import { createHash } from "node:crypto";
import { base58btc } from "multiformats/bases/base58";
import { sha256 } from "multiformats/hashes/sha2";
import { describe, expect, it } from "vitest";
import { prefixControlledBy } from "../src/controller.js";
import { signedCredentialToTurtle } from "../src/credential.js";
import type { FetchPort, HttpResponse } from "../src/fetch-port.js";
import { issueAgentAuthorization } from "../src/issue.js";
import { resolveBoundPolicy } from "../src/policy-binding.js";
import { verifyCredential } from "../src/verify.js";
import { parseAndVerifyCredential } from "../src/verify-rdf.js";
import { ACL_READ, AGENT, ISSUER, issuerKey, keyResolver } from "./helpers.js";

const POLICY_URL = "https://alice.example/policies/p1.ttl";
const POLICY_BODY =
  "<https://alice.example/policies/p1.ttl#agreement> a <http://www.w3.org/ns/odrl/2/Agreement> .";
const POLICY_OCTETS = new TextEncoder().encode(POLICY_BODY);

const BASE = { principal: ISSUER, agent: AGENT, action: ACL_READ } as const;

function response(body: Uint8Array, status = 200, contentType = "text/turtle"): HttpResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (n) => (n.toLowerCase() === "content-type" ? contentType : null) },
    text: async () => new TextDecoder().decode(body),
    arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
  };
}

function fakeFetch(routes: Record<string, Uint8Array | { status: number }>): FetchPort {
  return async (url) => {
    const r = routes[url];
    if (r === undefined) return response(new Uint8Array(), 404);
    return r instanceof Uint8Array ? response(r) : response(new Uint8Array(), r.status);
  };
}

function sriOf(octets: Uint8Array): string {
  return `sha256-${createHash("sha256").update(octets).digest("base64")}`;
}

async function multibaseOf(octets: Uint8Array): Promise<string> {
  const digest = await sha256.digest(octets);
  return base58btc.encode(digest.bytes);
}

describe("resolveBoundPolicy — embedded", () => {
  it("accepts an EMBEDDED policy graph (signed inline)", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      { ...BASE, embeddedPolicy: { "http://www.w3.org/ns/odrl/2/uid": POLICY_URL } },
      key,
    );
    const result = await resolveBoundPolicy(vc, {});
    expect(result.errors).toEqual([]);
    expect(result.policy?.form).toBe("embedded");
  });
});

describe("resolveBoundPolicy — bare reference is rejected (the D4 gap)", () => {
  it("REJECTS a bare, digest-less svc:policy IRI with POLICY_INTEGRITY", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization({ ...BASE, policy: POLICY_URL }, key);
    const result = await resolveBoundPolicy(vc, {
      fetch: fakeFetch({ [POLICY_URL]: POLICY_OCTETS }),
    });
    expect(result.policy).toBeUndefined();
    expect(result.errors.map((e) => e.code)).toContain("POLICY_INTEGRITY");
  });
});

describe("resolveBoundPolicy — by reference with digest", () => {
  it("accepts a reference whose fetched octets match the digestSRI", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      { ...BASE, policy: POLICY_URL, policyDigest: { digestSRI: sriOf(POLICY_OCTETS) } },
      key,
    );
    const result = await resolveBoundPolicy(vc, {
      fetch: fakeFetch({ [POLICY_URL]: POLICY_OCTETS }),
    });
    expect(result.errors).toEqual([]);
    expect(result.policy?.form).toBe("reference");
  });

  it("accepts a reference whose fetched octets match the digestMultibase", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      {
        ...BASE,
        policy: POLICY_URL,
        policyDigest: { digestMultibase: await multibaseOf(POLICY_OCTETS) },
      },
      key,
    );
    const result = await resolveBoundPolicy(vc, {
      fetch: fakeFetch({ [POLICY_URL]: POLICY_OCTETS }),
    });
    expect(result.errors).toEqual([]);
    expect(result.policy?.form).toBe("reference");
  });

  it("REJECTS when the fetched octets DO NOT match the signed digest", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      { ...BASE, policy: POLICY_URL, policyDigest: { digestSRI: sriOf(POLICY_OCTETS) } },
      key,
    );
    const tampered = new TextEncoder().encode(`${POLICY_BODY} # swapped after signing`);
    const result = await resolveBoundPolicy(vc, { fetch: fakeFetch({ [POLICY_URL]: tampered }) });
    expect(result.policy).toBeUndefined();
    expect(result.errors.map((e) => e.code)).toContain("POLICY_INTEGRITY");
  });

  it("REJECTS (fail-closed) a reference with a digest but no fetch injected", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      { ...BASE, policy: POLICY_URL, policyDigest: { digestSRI: sriOf(POLICY_OCTETS) } },
      key,
    );
    const result = await resolveBoundPolicy(vc, {});
    expect(result.errors.map((e) => e.code)).toContain("POLICY_INTEGRITY");
  });

  it("REJECTS when the policy document is unreachable (HTTP 404)", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      { ...BASE, policy: POLICY_URL, policyDigest: { digestSRI: sriOf(POLICY_OCTETS) } },
      key,
    );
    const result = await resolveBoundPolicy(vc, {
      fetch: fakeFetch({ [POLICY_URL]: { status: 404 } }),
    });
    expect(result.errors.map((e) => e.code)).toContain("POLICY_INTEGRITY");
  });
});

describe("resolveBoundPolicy — no policy", () => {
  it("returns no policy and no error when the credential binds none", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(BASE, key);
    const result = await resolveBoundPolicy(vc, {});
    expect(result.policy).toBeUndefined();
    expect(result.errors).toEqual([]);
  });
});

describe("verifyCredential ENFORCES policy binding (the High finding)", () => {
  it("REJECTS a bare-policy agent-authz credential with POLICY_INTEGRITY", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization({ ...BASE, policy: POLICY_URL }, key);
    const result = await verifyCredential(vc, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [POLICY_URL]: POLICY_OCTETS }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("POLICY_INTEGRITY");
  });

  it("ACCEPTS an embedded-policy credential (no fetch needed)", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      { ...BASE, embeddedPolicy: { "http://www.w3.org/ns/odrl/2/uid": POLICY_URL } },
      key,
    );
    const result = await verifyCredential(vc, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
    });
    expect(result.verified).toBe(true);
  });

  it("ACCEPTS a digest-referenced policy whose octets match", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      { ...BASE, policy: POLICY_URL, policyDigest: { digestSRI: sriOf(POLICY_OCTETS) } },
      key,
    );
    const result = await verifyCredential(vc, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [POLICY_URL]: POLICY_OCTETS }),
    });
    expect(result.verified).toBe(true);
  });

  it("parseAndVerifyCredential also REJECTS a bare-policy credential (RDF path)", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization({ ...BASE, policy: POLICY_URL }, key);
    const ttl = await signedCredentialToTurtle(vc);
    const result = await parseAndVerifyCredential(ttl, "text/turtle", {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("POLICY_INTEGRITY");
  });

  it("parseAndVerifyCredential ACCEPTS a digest-referenced policy (RDF path)", async () => {
    const key = await issuerKey();
    const vc = await issueAgentAuthorization(
      { ...BASE, policy: POLICY_URL, policyDigest: { digestSRI: sriOf(POLICY_OCTETS) } },
      key,
    );
    const ttl = await signedCredentialToTurtle(vc);
    const result = await parseAndVerifyCredential(ttl, "text/turtle", {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [POLICY_URL]: POLICY_OCTETS }),
    });
    expect(result.verified).toBe(true);
  });
});
