# Docker Sandboxes Questions for Outreach

**Purpose:** Document questions to ask Docker team about Sandboxes (`sbx`) when opportunity arises.

**Status:** Phase 1 research complete (2026-04-18). Some questions answered via public docs. Remaining questions prioritized for outreach.

---

## Phase 1 Findings (2026-04-18)

| Question | Answer | Source |
|----------|--------|--------|
| Is individual standalone use free? | **Yes** — confirmed by launch blog | docker.com/blog/docker-sandboxes-run-agents-in-yolo-mode-safely/ |
| What is the license? | **Proprietary (Docker Inc.)** | github.com/docker/sbx-releases LICENSE |
| Is there a public GitHub repo? | **Releases only** — `docker/sbx-releases`, no source | github.com/docker/sbx-releases |
| Does sbx have git safety features? | **No** — policy system is network-only | docs.docker.com/ai/sandboxes/network-policies/ |
| Is Linux supported? | **Partial** — install artifacts exist but provide container-based (not microVM) sandboxes | docs.docker.com/ai/sandboxes/, github.com/docker/sbx-releases |
| Is Docker Desktop required? | **No** — standalone CLI | docker.com/products/docker-sandboxes/ FAQ |

---

## Critical Questions

### Linux Support Timeline

- When will Linux installation instructions be published?
- Is Linux support a committed GA feature or exploratory?
- Will Linux use the same KVM backend mentioned in architecture docs?

### Experimental Status and GA Timeline

- What is the expected timeline for exiting "Experimental" status?
- What are the remaining blockers for GA?
- Will there be a beta program before GA?

---

## High Priority Questions

### Linux MicroVM Timeline (Updated)

- When will Linux get microVM-based sandboxes (not just legacy containers)?
- Is the KVM backend activation a technical or product decision?
- Will Linux microVM sandboxes match macOS/Windows feature parity?

### CLI Divergence (New)

- Will `docker sandbox` (Desktop plugin) and `sbx` (standalone) converge?
- Which CLI surface should third-party tools target for integration?
- Is there a version compatibility matrix between the two?

### Team/Enterprise Controls (Updated)

- What admin capabilities require a paid plan?
- Will network restrictions and filesystem policies be available in standalone mode?
- Is there a self-hosted option for enterprise?

### Licensing and Commercial Use

- What is the licensing model for Docker Sandboxes?
- Is individual standalone use free?
- What are the terms for teams/enterprise use?
- Are there any usage limits (concurrent sandboxes, API calls, etc.)?

### API Stability and Versioning

- Are there API versioning guarantees for `sbx` commands?
- What is the backward compatibility policy?
- How will breaking changes be communicated?

---

## Medium Priority Questions

### Customization and Extensibility

- Can `sbx` templates include pre-installed binaries?
- What is the recommended way to inject custom tools into sandboxes?
- Can file sync be configured for specific paths?

### Git Wrapper Injection

- What is the expected behavior of injected binaries after `sbx reset`?
- Is there a preferred mechanism for injecting git wrappers?
- Can `sbx exec --privileged` be restricted by policy?

### Credential Injection

- Does `sbx` support user-defined service credential injection?
- What is the mechanism for adding custom AI provider credentials?
- Are there any limitations on credential types or formats?

---

## Low Priority Questions

### Policy Enforcement

- Does `sbx` have plans for API-level policy enforcement (e.g., GitHub merge blocking)?
- Are there any plans for operation-level git guardrails?
- What is the roadmap for network policy features?

### Performance

- What are the performance characteristics of credential injection?
- Are there any known latency impacts for HTTP/HTTPS traffic through the proxy?
- What resource limits are recommended for AI development workflows?

---

## Notes

- Document all responses with dates and sources
- Update PLAN.md and PLAN-CHECKLIST.md with findings
- If Docker cannot answer critical questions, document as project risk

---

## Outreach Channels (When Ready)

- Docker Developer Advocate contact form
- Docker Community Slack
- Docker GitHub Discussions
- Docker blog comment section (when relevant posts are published)
