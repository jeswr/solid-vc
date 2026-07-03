// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The Bitstring Status List v1.0 status gate — exhaustive accept/reject matrix.
// A live signed status-list credential (published via signedCredentialToTurtle) is
// served through a fake fetch; the gate must ACCEPT a clear bit, DENY a set
// revocation/suspension bit with the DISTINCT code, and FAIL CLOSED on every
// unavailability / integrity failure (missing fetch, HTTP error, unverifiable or
// wrong-issuer or wrong-purpose or too-short list). Monotonicity + the
// status-is-under-the-proof property are covered too.

import { gzipSync } from "node:zlib";
import { base64url } from "multiformats/bases/base64";
import { describe, expect, it } from "vitest";
import { prefixControlledBy } from "../src/controller.js";
import { signedCredentialToTurtle } from "../src/credential.js";
import type { FetchPort, HttpResponse } from "../src/fetch-port.js";
import { issue } from "../src/issue.js";
import type {
  Credential,
  CredentialStatus,
  RevocationStore,
  VerifiableCredential,
} from "../src/types.js";
import { verifyCredential } from "../src/verify.js";
import { parseAndVerifyCredential } from "../src/verify-rdf.js";
import { STATUS_ENCODED_LIST, STATUS_PURPOSE, SVC_AUTHORIZES } from "../src/vocab.js";
import { AGENT, ISSUER, issuerKey, keyResolver } from "./helpers.js";

const LIST_URL = "https://alice.example/status/list-1";
const TOTAL_ENTRIES = 131072; // the Bitstring Status List minimum
const REVOKED_INDEX = 42;

/** Encode a bitstring (MSB-first) with `setBits` set → multibase-base64url GZIP. */
function encodeList(setBits: number[], entries = TOTAL_ENTRIES): string {
  const bytes = new Uint8Array(entries / 8);
  for (const i of setBits) {
    const b = bytes[i >>> 3] as number;
    bytes[i >>> 3] = b | (1 << (7 - (i & 7)));
  }
  return base64url.encode(gzipSync(bytes));
}

function response(body: string, status = 200, contentType = "text/turtle"): HttpResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (n) => (n.toLowerCase() === "content-type" ? contentType : null) },
    text: async () => body,
    arrayBuffer: async () => new TextEncoder().encode(body).buffer as ArrayBuffer,
  };
}

/** A fetch fixture over a URL→body|status map. */
function fakeFetch(routes: Record<string, string | { status: number }>): FetchPort {
  return async (url) => {
    const r = routes[url];
    if (r === undefined) return response("", 404);
    return typeof r === "string" ? response(r) : response("", r.status);
  };
}

/** Build + sign a BitstringStatusListCredential and serialise it to Turtle. */
async function signedStatusList(opts: {
  issuer?: string;
  purpose?: string;
  encodedList: string;
  key: Awaited<ReturnType<typeof issuerKey>>;
}): Promise<string> {
  const cred: Credential = {
    issuer: opts.issuer ?? ISSUER,
    id: LIST_URL,
    type: ["BitstringStatusListCredential"],
    credentialSubject: {
      id: `${LIST_URL}#list`,
      [STATUS_PURPOSE]: opts.purpose ?? "revocation",
      [STATUS_ENCODED_LIST]: opts.encodedList,
    },
  };
  const signed = await issue({ credential: cred, key: opts.key });
  return signedCredentialToTurtle(signed);
}

/** Build + sign an agent-authz hop carrying a credentialStatus entry. */
async function signedHop(
  key: Awaited<ReturnType<typeof issuerKey>>,
  status: CredentialStatus,
): Promise<VerifiableCredential> {
  const cred: Credential = {
    issuer: ISSUER,
    type: ["AgentAuthorizationCredential"],
    credentialSubject: { id: ISSUER, [SVC_AUTHORIZES]: AGENT },
    credentialStatus: status,
  };
  return issue({ credential: cred, key });
}

const REVOCATION_ENTRY: CredentialStatus = {
  type: "BitstringStatusListEntry",
  statusPurpose: "revocation",
  statusListIndex: String(REVOKED_INDEX),
  statusListCredential: LIST_URL,
};

describe("Bitstring Status List gate — accept", () => {
  it("verifies when the revocation bit is CLEAR", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const list = await signedStatusList({ key, encodedList: encodeList([]) });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(true);
    expect(result.errors).toEqual([]);
  });
});

describe("Bitstring Status List gate — deny (set bit)", () => {
  it("DENIES with REVOKED when the revocation bit is SET", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const list = await signedStatusList({ key, encodedList: encodeList([REVOKED_INDEX]) });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("REVOKED");
  });

  it("DENIES with SUSPENDED (distinct from REVOKED) when a suspension bit is SET", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, { ...REVOCATION_ENTRY, statusPurpose: "suspension" });
    const list = await signedStatusList({
      key,
      purpose: "suspension",
      encodedList: encodeList([REVOKED_INDEX]),
    });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    const codes = result.errors.map((e) => e.code);
    expect(codes).toContain("SUSPENDED");
    expect(codes).not.toContain("REVOKED");
  });
});

describe("Bitstring Status List gate — fail-closed on unavailability/integrity", () => {
  it("FAILS CLOSED (STATUS_RETRIEVAL_ERROR) when no fetch is injected", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("STATUS_RETRIEVAL_ERROR");
  });

  it("FAILS CLOSED when the status list returns HTTP 404", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: { status: 404 } }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("STATUS_RETRIEVAL_ERROR");
  });

  it("FAILS CLOSED when the status list is signed by a DIFFERENT issuer", async () => {
    const key = await issuerKey();
    const foreignKey = { ...(await issuerKey()), verificationMethod: "https://evil.example/#k" };
    // A validly-signed list, but issued by evil.example, not the hop issuer.
    const cred: Credential = {
      issuer: "https://evil.example/#me",
      id: LIST_URL,
      type: ["BitstringStatusListCredential"],
      credentialSubject: {
        id: `${LIST_URL}#list`,
        [STATUS_PURPOSE]: "revocation",
        [STATUS_ENCODED_LIST]: encodeList([]),
      },
    };
    const list = await signedCredentialToTurtle(await issue({ credential: cred, key: foreignKey }));
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key, foreignKey),
      isControlledBy: () => true,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("STATUS_RETRIEVAL_ERROR");
  });

  it("FAILS CLOSED when the bitstring is shorter than the minimum size", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const list = await signedStatusList({ key, encodedList: encodeList([], 1024) });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("STATUS_RETRIEVAL_ERROR");
  });

  it("FAILS CLOSED on an entry↔list statusPurpose mismatch", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY); // entry purpose = revocation
    const list = await signedStatusList({
      key,
      purpose: "suspension",
      encodedList: encodeList([]),
    });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("STATUS_RETRIEVAL_ERROR");
  });
});

describe("Bitstring Status List gate — monotonicity + tamper + opt-out", () => {
  it("stays REVOKED via the monotonic store even after a later CLEAR read", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const set = new Set<string>();
    const store: RevocationStore = {
      has: (k) => set.has(k),
      add: (k) => {
        set.add(k);
      },
    };
    const revokedList = await signedStatusList({ key, encodedList: encodeList([REVOKED_INDEX]) });
    const clearList = await signedStatusList({ key, encodedList: encodeList([]) });
    const opts = (list: string) => ({
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      revocationStore: store,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    const first = await verifyCredential(hop, opts(revokedList));
    expect(first.errors.map((e) => e.code)).toContain("REVOKED");
    // The bit is now cleared upstream, but monotonicity keeps it revoked.
    const second = await verifyCredential(hop, opts(clearList));
    expect(second.errors.map((e) => e.code)).toContain("REVOKED");
  });

  it("catches a STRIPPED credentialStatus via the signature (it is under the proof)", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const stripped = { ...hop };
    (stripped as { credentialStatus?: unknown }).credentialStatus = undefined;
    const result = await verifyCredential(stripped as VerifiableCredential, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({}),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("INVALID_SIGNATURE");
  });

  it("skips the gate entirely when checkStatus is false (verifies a revoked cred)", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const list = await signedStatusList({ key, encodedList: encodeList([REVOKED_INDEX]) });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      checkStatus: false,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(true);
  });
});

describe("roborev regressions — fail-open guards", () => {
  it("FAILS CLOSED on an out-of-range (large) statusListIndex instead of wrapping (32-bit)", async () => {
    const key = await issuerKey();
    // 2^33 is a safe integer but far beyond the bitstring — must be out-of-range, not
    // silently wrapped by `>>> 3` to a valid 32-bit index.
    const hop = await signedHop(key, { ...REVOCATION_ENTRY, statusListIndex: String(2 ** 33) });
    const list = await signedStatusList({ key, encodedList: encodeList([]) });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("STATUS_RETRIEVAL_ERROR");
  });

  it("parseAndVerifyCredential runs the status gate too (a fetched revoked VC → REVOKED)", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const hopTurtle = await signedCredentialToTurtle(hop);
    const list = await signedStatusList({ key, encodedList: encodeList([REVOKED_INDEX]) });
    const result = await parseAndVerifyCredential(hopTurtle, "text/turtle", {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("REVOKED");
  });

  it("parseAndVerifyCredential does NOT accept a VC whose only proof node is malformed", async () => {
    // A proof node missing sec:proofValue must FAIL, not verify with zero parsed proofs.
    const turtle = `
      @prefix cred: <https://www.w3.org/2018/credentials#> .
      @prefix sec: <https://w3id.org/security#> .
      <urn:vc:malformed> a cred:VerifiableCredential ;
        cred:issuer <https://alice.example/#me> ;
        cred:credentialSubject <https://bob.example/> ;
        sec:proof _:p .
      _:p a sec:DataIntegrityProof ;
        sec:cryptosuite "eddsa-rdfc-2022" ;
        sec:verificationMethod <https://alice.example/#key> ;
        sec:proofPurpose sec:assertionMethod .`;
    const result = await parseAndVerifyCredential(turtle, "text/turtle", {
      resolveKey: () => undefined,
      isControlledBy: () => true,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("INVALID_SIGNATURE");
  });
});

describe("roborev regression — status read is scoped to the SIGNED graph", () => {
  it("ignores an UNSIGNED status:encodedList injected on the proof node (stays REVOKED)", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    // A genuinely-signed status list with the revocation bit SET.
    const revokedList = await signedStatusList({ key, encodedList: encodeList([REVOKED_INDEX]) });
    // The proof node is NOT covered by the signature. An attacker appends a CLEAR
    // encodedList triple on it, hoping to un-revoke. The gate must read only the
    // signed encodedList and still return REVOKED.
    const proofMatch = revokedList.match(/sec:proof\s+(_:[\w-]+)/);
    expect(proofMatch).not.toBeNull();
    const proofNode = (proofMatch as RegExpMatchArray)[1];
    const clearList = encodeList([]);
    const tampered = `${revokedList}\n${proofNode} <https://www.w3.org/ns/credentials/status#encodedList> "${clearList}" .\n`;
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      fetch: fakeFetch({ [LIST_URL]: tampered }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("REVOKED");
  });
});

describe("roborev regressions — gate order + revocation-store fail-closed", () => {
  it("does NOT dereference the status list when the credential's CORE gates fail", async () => {
    const key = await issuerKey();
    const attackerKey = await issuerKey(); // same vm, different keypair → INVALID_SIGNATURE
    const hop = await signedHop(key, REVOCATION_ENTRY);
    let fetched = false;
    const spy: FetchPort = async () => {
      fetched = true;
      return response("", 500);
    };
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(attackerKey),
      isControlledBy: prefixControlledBy,
      fetch: spy,
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("INVALID_SIGNATURE");
    expect(fetched).toBe(false); // an unverified credential never triggers an outbound fetch
  });

  it("fails closed (STATUS_RETRIEVAL_ERROR) when revocationStore.has throws", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const store: RevocationStore = {
      has: () => {
        throw new Error("store unavailable");
      },
      add: () => {},
    };
    const list = await signedStatusList({ key, encodedList: encodeList([]) });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      revocationStore: store,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("STATUS_RETRIEVAL_ERROR");
  });

  it("still returns REVOKED when revocationStore.add throws (best-effort persistence)", async () => {
    const key = await issuerKey();
    const hop = await signedHop(key, REVOCATION_ENTRY);
    const store: RevocationStore = {
      has: () => false,
      add: () => {
        throw new Error("store write failed");
      },
    };
    const list = await signedStatusList({ key, encodedList: encodeList([REVOKED_INDEX]) });
    const result = await verifyCredential(hop, {
      resolveKey: keyResolver(key),
      isControlledBy: prefixControlledBy,
      revocationStore: store,
      fetch: fakeFetch({ [LIST_URL]: list }),
    });
    expect(result.verified).toBe(false);
    expect(result.errors.map((e) => e.code)).toContain("REVOKED");
  });
});
