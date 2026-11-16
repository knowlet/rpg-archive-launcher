# Bound the automatic Pixi source-map repair

At 7bca9e0bf51899ba45878faa39addc0dcde7d45c, the unanchored regex matches sourceMappingURL text inside JavaScript strings and prefixes of unrelated map URLs. Because play applies this repair to the Upper overlay, it can silently change script data while leaving the source archive intact.

ECMA-426 defines sourceMappingURL as a comment annotation and explicitly discusses ambiguity with JavaScript template text: https://tc39.es/ecma426/2024/#sec-linking-through-inline-annotations . This is a specification reference, not code reuse. A full JavaScript parser would be disproportionate for one known generated trailer. Narrow the existing regex to the exact standalone final pixi.js.map line, with horizontal padding and an optional LF/CRLF. Conservatively leave other spellings, inline markers, mid-file text and URL suffixes unchanged. This is a bounded cleanup, not a general JavaScript/source-map parser.

Tests cover quoted/template text, other map URLs, inline/mid-file comments, LF/CRLF, EOF without newline, idempotence, and the actual play-to-Upper repair path. No real game, runtime or macOS mount acceptance is claimed.
