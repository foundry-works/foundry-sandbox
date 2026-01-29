I have completed the security review of the `credential-isolation-gateway` plan.

# Review Summary

## Critical Blockers
Issues that MUST be fixed before this becomes a spec.

- **[Security]** Missing `/var/run/docker.sock` from Dangerous Paths
  - **Description:** The `DANGEROUS_PATHS` blocklist focuses on credential directories (`~/.ssh`, etc.) but omits the Docker socket. If a user mounts `/var/run/docker.sock` into a sandbox, they gain root access to the host and can run `docker inspect gateway` to reveal the real `GH_TOKEN` environment variable, completely bypassing the isolation.
  - **Impact:** Total compromise of the isolation system; attacker can steal the master GitHub token.
  - **Fix:** Add `/var/run/docker.sock` (and potentially other socket paths) to the `DANGEROUS_PATHS` array in `lib/validate.sh`.

- **[Security]** Undefined Input Validation for Gateway URL Parameters
  - **Description:** The Gateway constructs upstream URLs based on the `owner` and `repo` path parameters (`/git/<owner>/<repo>.git`). Without strict validation, this is vulnerable to directory traversal (e.g., `owner` = `..%2fevil.com`) or SSRF (forcing the gateway to talk to non-GitHub hosts).
  - **Impact:** An attacker could bypass the "GitHub only" restriction or target internal network services visible to the Gateway.
  - **Fix:** Explicitly specify strict regex validation for `owner` and `repo` (e.g., `^[a-zA-Z0-9_.-]+$`) in the Gateway spec and code.

## Major Suggestions
Significant improvements to strengthen the plan.

- **[Security]** Secure Token Injection Mechanism
  - **Description:** The plan states "Write token to tmpfs-mounted secret file" but doesn't specify *how* `commands/new.sh` performs this write. Using `docker exec` with the token as a command-line argument (e.g., `sh -c "echo $TOKEN > ..."`) leaks the token to the host process list (`ps`).
  - **Impact:** Local users on the host could briefly see session tokens in the process list.
  - **Fix:** Mandate that the token be written via `stdin` piping (e.g., `... <<< "$TOKEN" | docker exec -i ...`) to avoid command-line exposure.

- **[Security]** Run Gateway as Non-Root User
  - **Description:** The plan creates a `gateway/Dockerfile` but doesn't specify a user. Running the gateway as `root` (the Docker default) violates the principle of least privilege.
  - **Impact:** If the Gateway service is compromised via a vulnerability in the Python code, the attacker gains root access inside the Gateway container, making lateral movement or further exploitation easier.
  - **Fix:** Add a non-root user creation step to the `gateway/Dockerfile` and switch to it using the `USER` instruction.

- **[Security]** Session TTL / Garbage Collection
  - **Description:** The plan relies on `session/destroy` (triggered by `destroy.sh`) to remove sessions. If the host CLI crashes or a container is removed manually (e.g., `docker rm`), the session remains in the Gateway's memory indefinitely.
  - **Impact:** Stale sessions could accumulate, potentially allowing IP reuse attacks if a new container (with a different purpose) accidentally inherits a reused IP address associated with a valid, stale session.
  - **Fix:** Implement a "time-to-live" (TTL) for sessions (e.g., 24 hours) or a periodic cleanup task that invalidates sessions older than a certain threshold.

## Minor Suggestions
Smaller refinements.

- **[Security]** Restrict Socket Directory Permissions
  - **Description:** The plan mentions checking if the socket's parent directory is "world-writable". It should ideally be stricter.
  - **Fix:** Ensure the parent directory `$SANDBOX_STATE_DIR` is owned by the user and has `0700` permissions (accessible only by the owner).

- **[Security]** Block `file://` Protocol in Git Config
  - **Description:** While the Gateway is an HTTP proxy, the `git` client in the sandbox supports various protocols.
  - **Fix:** explicitly configure `git config --global protocol.file.allow never` in the Sandbox Dockerfile as a defense-in-depth measure against local file inclusion attacks, even though the primary vector is network-based.

## Questions
Clarifications needed before proceeding.

- **[Clarity]** How are repository scopes defined?
  - **Context:** The plan mentions the request includes `{repos: ["owner/repo"]}` and the Gateway enforces this scope. However, `sandbox new` is typically a generic command.
  - **Needed:** Clarify how the user specifies which repositories are allowed for a session. Does `sandbox new` accept a `--repo` flag, or does it default to allowing all repositories (effectively `*`)?

## Praise
What the plan does well.

- **[Architecture]** Network Isolation Strategy
  - **Why:** Using a dedicated `sandbox_internal` network with `icc=false` and no default gateway is a robust architectural pattern that fundamentally restricts what a compromised sandbox can do, regardless of software-level bugs.

- **[Security]** Tmpfs Token Storage
  - **Why:** Avoiding environment variables for token storage is a high-maturity security choice that effectively mitigates `/proc` snooping and `docker inspect` leaks.