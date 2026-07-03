// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The injectable network PORT for the SECURITY-CRITICAL gates that must dereference
// a remote resource — the document-resolved issuer–key controller check
// (src/controller.ts), the Bitstring Status List v1.0 status gate
// (src/status-list.ts), and the by-reference policy digest check
// (src/policy-binding.ts).
//
// WHY A PORT, NOT A HARD-WIRED FETCH. The verification core stays a pure, offline,
// browser-safe policy over PLAIN data + this one injected seam. It NEVER reaches for
// `globalThis.fetch` (which follows redirects, resolves DNS twice, and honours no
// SSRF policy). A caller MUST inject an SSRF-hardened fetch — the recommended one is
// `@jeswr/guarded-fetch/node`'s `nodeGuardedFetch`, wired for you by the
// `@jeswr/solid-vc/node` adapter (src/node.ts). The core's default when NO port is
// injected is FAIL-CLOSED: a network gate with no way to fetch denies, it never
// silently skips the check (a skipped revocation/controller check is an accept).
//
// `typeof globalThis.fetch` is assignable to {@link FetchPort} (a `Response` satisfies
// {@link HttpResponse}), so `nodeGuardedFetch` and a plain `fetch` both fit — but the
// narrow structural type keeps the reviewable surface tiny and lets a test pass a
// hand-built response without constructing a whole `Request`/`Response` pair.

/** The minimal response shape the VC gates read from an injected fetch. */
export interface HttpResponse {
  /** `true` for a 2xx status. */
  readonly ok: boolean;
  /** The HTTP status code. */
  readonly status: number;
  /** Case-insensitive header access (only `content-type` is read). */
  readonly headers: { get(name: string): string | null };
  /** The response body as text (for RDF documents). */
  text(): Promise<string>;
  /** The response body as raw octets (for the status-list bitstring + policy digest). */
  arrayBuffer(): Promise<ArrayBuffer>;
}

/**
 * The injectable network port: dereference an absolute http(s) URL. MUST be an
 * SSRF-hardened fetch (see the file header). Kept structurally compatible with
 * `typeof globalThis.fetch` so `@jeswr/guarded-fetch/node`'s `nodeGuardedFetch`
 * drops straight in.
 */
export type FetchPort = (url: string) => Promise<HttpResponse>;
