# MCP upstream authorization-server binding

This defensive conformance probe uses fixture observations rather than model judgment.
MCP 2026-07-28 Client Registration, [Authorization Server Binding](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#authorization-server-binding), requires pre-registered credentials to be keyed by the issuer that registered them and forbids reuse with another authorization server.
[RFC 9207 section 2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4) requires rejection of a mismatched authorization response issuer.

The control must prove a gateway token request using the registered static client at H and a nonce-correlated upstream call with an H-issued token.
Without that control, or without metadata rediscovery after the switch, the finding is skipped.
In own mode, a static client secret at E fails at high severity; a static client ID alone at E fails at medium severity.
In mirror mode, H's issued-code correlation and its matching PKCE S256 transform at E fail at high severity; H's code without a verifier also fails.
Complete, exercised evidence without the specified exposure passes; incomplete negative evidence is an error.
Secrets, authorization codes and PKCE verifiers must never appear in the report.
