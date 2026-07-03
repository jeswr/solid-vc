// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Verifiable Presentations: challenge + domain binding + HOLDER binding (this note's
// §"Presenting a chain"). The presenter is the AGENT (svc:authorizes); it must PROVE
// control of that WebID (authentication-purpose proof over the presentation graph,
// binding the verifier's challenge/domain) — holding the credential is not enough.

import { describe, expect, it } from "vitest";
import { prefixControlledBy } from "../src/controller.js";
import { issue, issueAgentAuthorization } from "../src/issue.js";
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

describe("verifyPresentation — roborev regressions", () => {
  it("rejects a SUBSTITUTED same-id credential (the proof binds the payload digest)", async () => {
    const issuerK = await issuerKey();
    const holderK = await generateKeyPairForSuite(HOLDER_VM, "Ed25519");
    const hop1 = await issueAgentAuthorization(
      { principal: ISSUER, agent: AGENT, action: ACL_READ, id: "urn:hop:1" },
      issuerK,
    );
    const vp = await signPresentation({ holder: AGENT, verifiableCredential: [hop1] }, holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    // A DIFFERENT, validly-signed credential with the SAME id, swapped in post-signing.
    const hop2 = await issueAgentAuthorization(
      {
        principal: ISSUER,
        agent: AGENT,
        action: "http://www.w3.org/ns/auth/acl#Write",
        id: "urn:hop:1",
      },
      issuerK,
    );
    const substituted = { ...vp, verifiableCredential: [hop2] };
    const result = await verifyPresentation(substituted, {
      resolveKey: keyResolver(issuerK, holderK),
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("INVALID_SIGNATURE");
  });

  it("does not throw on a malformed proof (proof: null) — returns verified:false", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation(presentationOf(hop), holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const malformed = { ...vp, proof: null } as unknown as typeof vp;
    const result = await verifyPresentation(malformed, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
  });

  it("does NOT honour svc:authorizes on a non-AgentAuthorizationCredential", async () => {
    const issuerK = await issuerKey();
    const holderK = await generateKeyPairForSuite(HOLDER_VM, "Ed25519");
    // A plain credential (NOT agent-authz) that merely carries an svc:authorizes claim.
    const generic = await issue({
      credential: {
        issuer: ISSUER,
        credentialSubject: {
          id: "https://someone.example/#me",
          "https://w3id.org/jeswr/solid-vc#authorizes": AGENT,
        },
      },
      key: issuerK,
    });
    const vp = await signPresentation({ holder: AGENT, verifiableCredential: [generic] }, holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const result = await verifyPresentation(vp, {
      resolveKey: keyResolver(issuerK, holderK),
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("HOLDER_UNVERIFIED");
  });
});

describe("verifyPresentation — malformed inputs never throw (roborev round 2)", () => {
  it("handles verifiableCredential: [null] without throwing", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation(presentationOf(hop), holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const broken = { ...vp, verifiableCredential: [null] } as unknown as typeof vp;
    const result = await verifyPresentation(broken, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
  });

  it("handles a proof missing proofPurpose without throwing", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation(presentationOf(hop), holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const { proofPurpose: _p, ...proofNoPurpose } = vp.proof;
    const broken = { ...vp, proof: proofNoPurpose } as unknown as typeof vp;
    const result = await verifyPresentation(broken, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("INVALID_SIGNATURE");
  });
});

describe("verifyPresentation — malformed inputs never throw (roborev round 3)", () => {
  it("fails a mixed proof array [validProof, null] (every proof must be valid)", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const vp = await signPresentation(presentationOf(hop), holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const single = Array.isArray(vp.proof) ? vp.proof[0] : vp.proof;
    const broken = { ...vp, proof: [single, null] } as unknown as typeof vp;
    const result = await verifyPresentation(broken, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("INVALID_SIGNATURE");
  });

  it("does not throw when an embedded credential has proof: null", async () => {
    const { holderK, hop, resolveKey } = await fixture();
    const brokenHop = { ...hop, proof: null } as unknown as typeof hop;
    const vp = await signPresentation({ holder: AGENT, verifiableCredential: [hop] }, holderK, {
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    const broken = { ...vp, verifiableCredential: [brokenHop] } as unknown as typeof vp;
    const result = await verifyPresentation(broken, {
      resolveKey,
      isControlledBy: prefixControlledBy,
      challenge: CHALLENGE,
      domain: DOMAIN,
    });
    expect(result.verified).toBe(false);
  });
});
