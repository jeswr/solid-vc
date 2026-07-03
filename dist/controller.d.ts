import type { FetchPort } from "./fetch-port.js";
/** An async controller-binding check: is `verificationMethod` controlled by `issuer`? */
export type ControlledByCheck = (verificationMethod: string, issuer: string) => boolean | Promise<boolean>;
/**
 * The UNSAFE string-prefix heuristic, kept as an EXPLICIT, named opt-in (never the
 * default). The method IRI must equal the issuer IRI or start with `<issuer>#` /
 * `<issuer>/`. Documented unsafe (see the file header); use only in tests or a
 * closed deployment where every WebID is single-tenant and same-origin. A conforming
 * chain verifier MUST override this with {@link documentResolvedControlledBy}.
 */
export declare function prefixControlledBy(verificationMethod: string, issuer: string): boolean;
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
export declare function documentResolvedControlledBy(fetch: FetchPort, expectedProofPurpose?: string): ControlledByCheck;
//# sourceMappingURL=controller.d.ts.map