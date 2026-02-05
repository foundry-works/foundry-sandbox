# ADR-003: Policy Engine Design

## Status

Accepted

Date: 2026-02-04
Implemented: 2026-02-05

### Update (2026-02-05)

Gateway consolidated into **unified-proxy** (see [ADR-005](005-unified-proxy.md)). Allowlist moved from `gateway/allowlist.conf` to `config/allowlist.yaml`. Policy paths moved from `/etc/gateway/policies/` to `/etc/proxy/policies/`.

### Implementation Notes

Policy engine implemented in `unified-proxy/addons/policy_engine.py`:

- **Hierarchical policies** - Container-specific, sandbox-wide, and global fallbacks
- **Multiple policy types** - Domain allowlist, rate limits, content filters
- **Default-deny posture** - Explicit allow required for all operations
- **Integration** - Works with rate_limiter.py and circuit_breaker.py addons
- **Audit logging** - Policy decisions logged with context for debugging

## Context

The unified proxy currently implements a simple, flat domain allowlist in `config/allowlist.yaml` that controls which external domains are accessible from sandbox containers. As the system scales to support multiple policy types (domain allowlisting, rate limiting, content filtering) and complex scenarios (per-container policies, global policies, default behaviors), we need a more sophisticated policy evaluation framework that:

1. **Handles policy complexity**: Moving beyond simple domain allowlists to support rate limits, content filtering, and other policy types
2. **Supports multiple policy scopes**: Container-specific policies, sandbox-wide policies, and global fallback policies
3. **Resolves policy conflicts clearly**: When multiple policies apply to the same request, we need deterministic evaluation order
4. **Enforces least privilege**: Default-deny model ensures only explicitly allowed operations succeed
5. **Provides audit visibility**: Clear logging of which policies permitted/denied requests and why

### Current System

- **Allowlist file**: `config/allowlist.yaml` - single source of truth for domain allowlists
- **Format**: Domains with optional type tags (github, ai, research, etc.)
- **Wildcards**: Support for wildcard domains (*.example.com) matching any subdomain
- **Firewall integration**: Allowlist coordinates with DNS and limited-mode firewall rules

The current system works well for its single purpose (domain allowlisting) but lacks structure for evolving requirements:
- No per-container policy overrides
- No rate limiting or content filtering
- No explicit conflict resolution mechanism
- No policy versioning or audit trail

### Constraints

1. **Backward compatibility**: Existing allowlist.conf format must be supported
2. **Performance**: Policy evaluation must not add significant latency to request handling
3. **Simplicity**: Operators should be able to understand and modify policies without deep system knowledge
4. **Security**: Must maintain fail-closed (default-deny) posture
5. **Multi-tenant**: Different sandboxes may have different policy requirements

## Decision

Implement a **hierarchical policy engine** with the following design:

### 1. Policy Structure

Policies are organized into multiple types, each with a specific purpose:

```yaml
# Policy Type: Allowlist (domains)
- type: allowlist
  scope: global | container | sandbox
  priority: integer (0-100, higher wins)
  match:
    domain: "*.github.com"
    domain_type: "github"  # optional tag for categorization
  action: allow | deny

# Policy Type: RateLimit
- type: rate_limit
  scope: global | container | sandbox
  priority: integer
  match:
    domain: "api.github.com"
  action: rate_limit
  config:
    requests_per_minute: 60
    burst_size: 10

# Policy Type: ContentFilter
- type: content_filter
  scope: global | container | sandbox
  priority: integer
  match:
    domain: "api.anthropic.com"
    path_pattern: "/v1/messages"
  action: inspect | allow | deny
  config:
    max_size_bytes: 1000000
    blocked_headers: ["x-debug-mode"]
```

### 2. Evaluation Order (Container-Specific → Global → Default Deny)

All policies are evaluated in this strict order:

```
REQUEST ARRIVES
    ↓
1. CONTAINER-SPECIFIC POLICIES (priority 0-100)
   - Look for policies matching scope="container" AND this container's ID
   - Evaluate matching policies in descending priority order
   - If a policy matches: apply action (allow/deny/rate_limit/inspect) → DONE
    ↓ (if no match)
2. SANDBOX-WIDE POLICIES (priority 0-100)
   - Look for policies matching scope="sandbox" AND this sandbox's ID
   - Evaluate matching policies in descending priority order
   - If a policy matches: apply action → DONE
    ↓ (if no match)
3. GLOBAL POLICIES (priority 0-100)
   - Look for policies matching scope="global"
   - Evaluate matching policies in descending priority order
   - If a policy matches: apply action → DONE
    ↓ (if no match)
4. DEFAULT DENY
   - No policies matched
   - ACTION: DENY REQUEST
   - Log: "Request denied: no matching allow policy" + request details
```

**Key principle**: The first matching policy wins. Higher-priority policies shadow lower-priority ones at the same scope level.

### 3. Rule Precedence and Conflict Resolution

#### Rule Precedence (from highest to lowest)

1. **Scope hierarchy**: Container-specific > Sandbox-wide > Global
   - A container-specific allow policy cannot be overridden by a global deny policy
   - A sandbox-wide policy overrides global policies at the same priority

2. **Priority value**: Higher numerical priority wins within the same scope
   - Priority range: 0-100 (higher is stronger)
   - Policies at same priority level: first-match-wins (stable sort by rule index/insertion order)

3. **Policy type**: Order of evaluation
   - Explicit allows (allowlist) evaluated before general rules
   - Rate limits applied after allow is confirmed
   - Content filters applied during request processing

#### Conflict Resolution Examples

**Example 1: Container override of global policy**
```
Global Policy (priority 50):  domain=api.github.com → action=deny
Container Policy (priority 60): domain=api.github.com → action=allow
Result: ALLOW (container-specific scope takes precedence, even at lower priority)
```

**Example 2: Priority-based resolution**
```
Global Policy A (priority 50): domain=*.github.com → action=allow
Global Policy B (priority 60): domain=api.github.com → action=deny
Result: DENY (higher priority wins within global scope)
```

**Example 3: First-match-wins at same priority**
```
Global Policy A (priority 50, index 0): domain=*.github.com → action=allow
Global Policy B (priority 50, index 1): domain=api.github.com → action=deny
Request: api.github.com
Result: ALLOW (first match wins, policy A evaluated first)
```

### 4. Policy Types

#### Allowlist (Domain Allowlist)

**Purpose**: Control which external domains are accessible

**Matching**: Domain name (with wildcard support)

**Actions**:
- `allow`: Request is permitted
- `deny`: Request is denied

**Configuration**:
```yaml
type: allowlist
match:
  domain: "api.github.com"          # exact domain
  # OR
  domain: "*.github.com"             # wildcard domain
  domain_type: "github"              # optional categorization tag
action: allow | deny
```

**Example**:
```yaml
- type: allowlist
  scope: global
  priority: 50
  match: { domain: "*.github.com", domain_type: "github" }
  action: allow

- type: allowlist
  scope: global
  priority: 50
  match: { domain: "api.anthropic.com", domain_type: "ai" }
  action: allow
```

#### Rate Limit

**Purpose**: Control request frequency to prevent abuse or DoS

**Matching**: Domain and optional path pattern

**Actions**:
- `rate_limit`: Allow request if under limit, deny if over limit
- `allow`: Permit with no rate limiting

**Configuration**:
```yaml
type: rate_limit
match:
  domain: "api.github.com"
  path_pattern: "/graphql"  # optional regex
action: rate_limit
config:
  requests_per_minute: 60
  burst_size: 10            # allow short bursts
  window_seconds: 60        # sliding window duration
  key: "ip" | "session" | "container"  # rate limit scope
```

**Example**:
```yaml
- type: rate_limit
  scope: global
  priority: 40
  match: { domain: "api.anthropic.com" }
  action: rate_limit
  config:
    requests_per_minute: 100
    burst_size: 20
    key: "container"  # limit per container
```

#### Content Filter

**Purpose**: Inspect and control request/response content

**Matching**: Domain and path pattern

**Actions**:
- `inspect`: Examine request, allow or deny based on content rules
- `allow`: Permit without inspection
- `deny`: Block without inspection

**Configuration**:
```yaml
type: content_filter
match:
  domain: "api.anthropic.com"
  path_pattern: "/v1/messages"
action: inspect | allow | deny
config:
  max_request_size_bytes: 1000000
  max_response_size_bytes: 5000000
  blocked_headers: ["x-debug-mode"]
  blocked_request_patterns: ["secret=.*"]  # regex redaction
  sensitive_fields: ["password", "token"]  # auto-redact in logs
```

**Example**:
```yaml
- type: content_filter
  scope: global
  priority: 30
  match: { domain: "api.anthropic.com", path_pattern: "/v1/.*" }
  action: inspect
  config:
    max_request_size_bytes: 1000000
    sensitive_fields: ["api_key", "authorization"]
```

### 5. Policy Storage and Evaluation

#### File-Based Policy Format

Policies stored in `/etc/proxy/policies/` with clear structure:

```
/etc/proxy/policies/
├── global/
│   ├── 00-allowlist.yaml      # Global allowlist policies
│   ├── 10-rate-limits.yaml    # Global rate limit policies
│   └── 20-content-filters.yaml
├── sandboxes/
│   └── {sandbox-id}/
│       ├── allowlist.yaml     # Sandbox-specific policies
│       └── overrides.yaml
└── containers/
    └── {container-id}/
        ├── allowlist.yaml     # Container-specific policies
        └── rate-limits.yaml
```

#### Evaluation Algorithm

```python
def evaluate_policy(request) -> PolicyDecision:
    """
    Evaluate request against policy hierarchy.
    Returns: (action, reason, matching_policy_id)
    """

    # 1. Container-specific scope
    matching_policy = find_matching_policy(
        policies=container_policies,
        request=request,
        scope="container"
    )
    if matching_policy:
        return apply_policy(matching_policy, request)

    # 2. Sandbox-wide scope
    matching_policy = find_matching_policy(
        policies=sandbox_policies,
        request=request,
        scope="sandbox"
    )
    if matching_policy:
        return apply_policy(matching_policy, request)

    # 3. Global scope
    matching_policy = find_matching_policy(
        policies=global_policies,
        request=request,
        scope="global"
    )
    if matching_policy:
        return apply_policy(matching_policy, request)

    # 4. Default deny
    return PolicyDecision(
        action=DENY,
        reason="No matching allow policy (default deny)",
        policy_id="default-deny"
    )

def find_matching_policy(policies, request, scope):
    """Find highest-priority matching policy in scope."""
    matching = [
        p for p in policies
        if p.scope == scope and p.matches(request)
    ]
    if not matching:
        return None

    # Sort by priority descending, then by insertion order
    matching.sort(key=lambda p: (-p.priority, p.index))
    return matching[0]
```

### 6. Backward Compatibility

The current `config/allowlist.yaml` format is automatically converted to policy format on startup:

```yaml
# Old format in allowlist.conf
github.com github
api.github.com github
*.openai.com ai

# Auto-converted to policies
- type: allowlist
  scope: global
  priority: 50
  match: { domain: "github.com", domain_type: "github" }
  action: allow

- type: allowlist
  scope: global
  priority: 50
  match: { domain: "api.github.com", domain_type: "github" }
  action: allow

- type: allowlist
  scope: global
  priority: 50
  match: { domain: "*.openai.com", domain_type: "ai" }
  action: allow
```

The allowlist.conf remains the single source of truth for global allowlist policies. New policy types (rate limiting, content filtering) are defined in separate YAML files.

## Consequences

### Positive

1. **Extensibility**: New policy types (rate limiting, content filtering, authentication) can be added without redesigning the core evaluation engine
2. **Flexibility**: Different sandboxes/containers can have custom policies without global impact
3. **Clarity**: Explicit evaluation order eliminates ambiguity about which policy applies
4. **Auditability**: Policy decisions are logged with matching policy ID for investigation
5. **Fail-closed**: Default-deny model ensures only explicitly allowed operations succeed
6. **Backward compatible**: Existing allowlist.conf continues to work without modification
7. **Operator-friendly**: Policy YAML syntax is human-readable and easy to modify

### Negative

1. **Complexity**: More sophisticated than flat allowlist - requires operators to understand scope hierarchy
2. **Performance overhead**: Policy evaluation adds latency compared to simple allowlist lookup
   - Mitigation: Cache compiled policies, use efficient matching algorithms (trie for domains)
3. **Configuration explosion**: As operators add container-specific policies, configuration becomes harder to manage
   - Mitigation: Provide templating/inheritance mechanisms, policy audit tools
4. **Priority confusion**: Operators may misunderstand priority semantics (higher number = stronger)
   - Mitigation: Clear documentation, validation tools to warn of unexpected configurations
5. **Rate limiting state**: Rate limit policies require in-memory state (counters) that doesn't survive proxy restart
   - Mitigation: Accept per-session rate limit resets as acceptable; monitor for issues

### Neutral

1. **Memory usage**: Policy cache increases memory footprint (acceptable for typical policy counts)
2. **Hot reload complexity**: If policies can be hot-reloaded without restart, adds implementation complexity
   - Decision: Require proxy restart for policy changes (simpler, adequate for most use cases)
3. **Separate policy files**: Organization into multiple files adds to deployment package size (negligible)

## Alternatives Considered

### Alternative 1: Single Flat Policy File

Store all policies (global, sandbox, container) in a single large YAML file.

**Rejected because:**
- Doesn't scale - hard to manage hundreds of container-specific policies in one file
- Lack of organization makes it easy to create duplicate policies
- More difficult to version-control changes by scope

### Alternative 2: Database-Backed Policy Store

Store policies in a database (SQLite, PostgreSQL) instead of files.

**Rejected because:**
- Adds operational complexity (database must be running, backed up)
- Reduces portability (harder to ship policies with container)
- Makes troubleshooting harder (can't inspect policies as simple text)
- File-based approach sufficient for expected policy volumes

### Alternative 3: Reject Container-Specific Policies (Global Only)

Only support global policies, no per-sandbox or per-container overrides.

**Rejected because:**
- Reduces flexibility (different workloads have different requirements)
- Doesn't scale to multi-tenant scenarios
- Violates principle of least privilege (can't restrict individual containers)

### Alternative 4: Implicit Allow (Whitelist + Implicit Deny Edge Cases)

Instead of strict default-deny, implicitly allow if no policy matches.

**Rejected because:**
- Violates security principle of fail-closed
- Operators might forget to block dangerous domains
- Creates security vulnerability if new endpoints are added to external services

### Alternative 5: Dynamic Policy Evaluation

Support hot-reloading policies without proxy restart.

**Rejected because:**
- Adds complexity to policy loading/caching logic
- Increases risk of inconsistent state during reload
- File-based approach with restart is simpler and adequate
- Restart is quick in containerized environment

## References

- [Security Architecture](../security/security-architecture.md) - Security design principles
- [Credential Isolation Threat Model](../security/credential-isolation.md) - Threat model that informed policy needs
- [Network Isolation](../security/network-isolation.md) - Network architecture that policies control
- [Current Allowlist Implementation](../../config/allowlist.yaml) - Domain allowlist configuration
- [Architecture Overview](../architecture.md) - System architecture context
