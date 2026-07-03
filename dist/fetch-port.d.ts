/** The minimal response shape the VC gates read from an injected fetch. */
export interface HttpResponse {
    /** `true` for a 2xx status. */
    readonly ok: boolean;
    /** The HTTP status code. */
    readonly status: number;
    /** Case-insensitive header access (only `content-type` is read). */
    readonly headers: {
        get(name: string): string | null;
    };
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
//# sourceMappingURL=fetch-port.d.ts.map