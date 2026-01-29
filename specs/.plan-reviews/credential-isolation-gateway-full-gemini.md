Here is the comprehensive review of the `credential-isolation-gateway` plan.

# Review Summary

## Critical Blockers
Issues that MUST be fixed before this becomes a spec.

- **[Completeness]** Undefined Host-to-Gateway Credential Handover
  - **Description:** The plan states `commands/new.sh` will "call gateway session creation," but doesn't specify *how* the host CLI communicates securely with the Gateway container. Exposing the Gateway API via a published port (e.g., `localhost:8080`) allows any process on the host to potentially create sessions or attack the gateway.
  - **Impact:** Security vulnerability (credential interception) or implementation blocker (CLI cannot reach Gateway).
  - **Fix:** Do not expose the `/session/create` endpoint via HTTP port binding. Instead, use `docker exec -i <gateway_container> python create_session.py` to pass the credentials via `stdin`. This ensures only the process capable of controlling Docker can seed the credentials.

- **[Feasibility]** Git Smart HTTP Protocol Handling in Flask
  - **Description:** Implementing a Git proxy in Flask is not just simple URL routing. Git operations (especially `push` and large `clone`) use streaming, specific Content-Types, and Chunked Transfer Encoding. A naive Flask implementation usually buffers requests/responses, which will fail on large repos or time out.
  - **Impact:** `git clone` fails for large repos; `git push` hangs or fails; high memory usage in the Gateway.
  - **Fix:** Explicitly require the use of stream-capable request handling (e.g., `requests.get(..., stream=True)` upstream and Flask generators downstream). Ensure the proxy handles `Expect: 100-continue` headers correctly.

## Major Suggestions
Significant improvements to strengthen the plan.

- **[Risk]** Fragility of Static Domain Allowlists
  - **Description:** The plan proposes a static `tinyproxy.conf` allowlist. Modern package managers (npm, pip) rely on CDNs and redirect domains that change frequently or are vast (e.g., `files.pythonhosted.org`, `registry.npmjs.org`, various AWS S3 buckets for binaries).
  - **Impact:** Users will constantly encounter broken builds ("connection refused") when trying to install standard packages, leading to frustration and manual patching.
  - **Fix:** Research and include a base set of "Safe wildcard domains" for standard package managers in the spec. Alternatively, implement a "Learning Mode" or a user-editable `allowlist.txt` mounted into the Gateway container that doesn't require rebuilding the image.

- **[Completeness]** Git LFS Support
  - **Description:** The plan does not mention Git Large File Storage (LFS). LFS clients often make separate API calls to retrieve batch objects and then upload/download blobs to different URLs (often S3/Azure Blob).
  - **Impact:** If a user clones a repo with LFS assets, the initial clone might work (proxied), but the LFS download will fail if the LFS server URL is not rewritten or allowlisted.
  - **Fix:** Explicitly mark Git LFS as "Out of Scope" for V1, or analyze if the current rewriting logic covers LFS batch APIs.

- **[Architecture]** Handling "One Gateway per Sandbox" vs "Global Gateway"
  - **Description:** The architecture implies a Gateway service inside `docker-compose.yml`. This creates a 1:1 mapping (One Gateway per Sandbox). This is good for isolation but resource-heavy (running a Flask app + dnsmasq + tinyproxy for *every* sandbox).
  - **Impact:** Higher memory footprint per sandbox.
  - **Fix:** Confirm this trade-off is intentional. Since `foundry-sandbox` seems to focus on single-instance usage, this is likely acceptable, but explicitly stating "One Gateway instance per Sandbox" in the Architecture section clarifies the resource model.

## Minor Suggestions
Smaller refinements.

- **[Completeness]** Dangerous Path Additions
  - **Description:** The blocklist misses the Docker socket, which is a common privilege escalation path.
  - **Fix:** Add `/var/run/docker.sock` and `/run/docker.sock` to `DANGEROUS_PATHS`.

- **[Clarity]** Gateway Token Storage
  - **Description:** It's implied the Gateway stores credentials in memory.
  - **Fix:** Explicitly state "Credentials are stored in-memory only and lost on container restart" to clarify the security posture.

## Questions
Clarifications needed before proceeding.

- **[Sequencing]** When does the Gateway start relative to the Sandbox?
  - **Context:** If the sandbox container starts *before* the Gateway is ready, the initial `git config` or `pip install` might fail DNS resolution.
  - **Needed:** Does `docker-compose` `depends_on` with `condition: service_healthy` need to be specified for the Sandbox service pointing to the Gateway?

## Praise
What the plan does well.

- **[Architecture]** Network Isolation Strategy
  - **Why:** Using Docker's `internal` network combined with a dedicated Gateway/Proxy is the industry-standard "Sidecar" pattern for egress filtering. It is robust and avoids complex host-level iptables manipulation.

- **[Security]** Repository-Scoped Session Tokens
  - **Why:** Issuing a generated token to the sandbox that is only valid for specific repositories (checked by the Gateway) is a significantly stronger security posture than simply passing the raw GitHub token, even if proxied.