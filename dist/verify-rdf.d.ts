import type { DatasetCore } from "@rdfjs/types";
import type { VerificationResult } from "./types.js";
import type { VerifyCredentialOptions } from "./verify.js";
/** The result of {@link parseAndVerifyCredential}: the verdict plus the parsed graph. */
export interface ParsedVerification extends VerificationResult {
    /** The parsed RDF dataset (so a caller can read further claims, e.g. `encodedList`). */
    readonly dataset?: DatasetCore;
    /** The verified credential's IRI (the graph node), when a single credential was found. */
    readonly credentialId?: string;
}
/**
 * Parse a serialized VC (`body` in `contentType` — Turtle / JSON-LD / N-Quads) and
 * verify it over the parsed graph. `options.baseIRI` (default the empty base) resolves
 * relative IRIs; pass the retrieval URL so a document's `<#...>` terms resolve. The
 * gates are identical to {@link verifyCredential}; fail-closed on a parse failure
 * (MALFORMED) and on an ambiguous document (0 or >1 credential nodes).
 */
export declare function parseAndVerifyCredential(body: string, contentType: string, options: VerifyCredentialOptions & {
    readonly baseIRI?: string;
}): Promise<ParsedVerification>;
//# sourceMappingURL=verify-rdf.d.ts.map