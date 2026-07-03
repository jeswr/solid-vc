// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Verifiable Presentations: challenge + domain binding + HOLDER binding (this note's
// §"Presenting a chain"). The presenter is the AGENT (svc:authorizes); it must PROVE
// control of that WebID (authentication-purpose proof over the presentation graph,
// binding the verifier's challenge/domain) — holding the credential is not enough.

import { describe, expect, it } from "vitest";
import { prefixControlledBy } from "../src/controller.js";
import { issueAgentAuthorization } from "../src/issue.js";
import { generateKeyPairForSuite } from "../src/keys.js";
import { signPresentation, verifyPresentation } from "../src/presentation.js";
import type { Presentation, VerifiableCredential } from "../src/types.js";
import { ACL_READ, AGENT, ISSUER, issuerKey, keyResolver } from "./helpers.js";

const CHALLENGE = "c-8f21-issued-by-verifier";
const DOMAIN = "https://rp.example/login";
const HOLDER_VM = `${AGENT}#key`;

async function fixture() {
  const issuerK = await issuerKey(); // alice — signs the hop credential
  const holderK = await generateKeyPairForSuite(HOLDER_VM, "Ed25519"); // the agent — presents
  const hop = await issueAgentAuthorization(
    { principal: ISSUER, agent: AGENT, action: ACL_READ },
    issuerK,
  );
  const resolveKey = keyResolver(issuerK, holderK);
  return { issuerK, holderK, hop, resolveKey };
}

function presentationOf(hop: VerifiableCredential, holder = AGENT): Presentation {
  return { holder, verifiableCredential: [hop] };
}

describe("verifyPresentation — happy path", () => {
  it("verifies a presentation with matching challenge + domain and a bound holder", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation(presentationOf(hop), holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const result = await verifyPresentation(vp, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.holder).toBe(AGENT);
  });
});

describe("verifyPresentation — challenge/domain (replay protection)", () => {
  it("rejects a mismatched challenge (a replayed presentation)", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation(presentationOf(hop), holderK, {
      challenge: "an-old-challenge",
      domain: DOMAIN,
    });
    const result = await verifyPresentation(vp, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("CHALLENGE_MISMATCH");
  });

  it("rejects a mismatched domain (presented to the wrong relying party)", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation(presentationOf(hop), holderK, {
      challenge: CHALLENGE,
      domain: "https://evil.example",
    });
    const result = await verifyPresentation(vp, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("DOMAIN_MISMATCH");
  });

  it("detects a tampered challenge (it is under the presentation signature)", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation(presentationOf(hop), holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const forged = { ...vp, proof: { ...vp.proof, challenge: "swapped" } } as typeof vp;
    const result = await verifyPresentation(forged, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: "swapped",
      domain: DOMAIN,
    });
    // challenge now "matches" the forged value, but the signature no longer verifies.
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("INVALID_SIGNATURE");
  });
});

describe("verifyPresentation — holder binding", () => {
  it("rejects a presentation with no holder", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation({ verifiableCredential: [hop] }, holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const result = await verifyPresentation(vp, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("HOLDER_UNVERIFIED");
  });

  it("rejects a holder the credential does not name (not subject nor authorized agent)", async () => {
    const { issuerK, hop } = await fixture();
    const strangerK = await generateKeyPairForSuite("https://carol.example/#key", "Ed25519");
    const vp = await signPresentation(presentationOf(hop, "https://carol.example/#me"), strangerK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const result = await verifyPresentation(vp, {
      resolveKey: keyResolver(issuerK, strangerK),
      isControlledBy: () => true,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    // Carol proved control of her key, but the credential names AGENT, not carol.
    expect(result.errors.map((e) => e.code)).toContain("HOLDER_UNVERIFIED");
  });
});

describe("verifyPresentation — embedded credential validity propagates", () => {
  it("rejects when an embedded credential is tampered", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const subj = Array.isArray(hop.credentialSubject)
      ? hop.credentialSubject[0]
      : hop.credentialSubject;
    const tamperedHop: VerifiableCredential = {
      ...hop,
      credentialSubject: {
        ...subj,
        "https://w3id.org/jeswr/solid-vc#action": "http://www.w3.org/ns/auth/acl#Write",
      },
    };
    const vp = await signPresentation(presentationOf(tamperedHop), holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const result = await verifyPresentation(vp, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("INVALID_SIGNATURE");
  });
});
