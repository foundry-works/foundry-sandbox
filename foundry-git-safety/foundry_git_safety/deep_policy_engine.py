"""Deep policy rule engine, circuit breaker, and policy loading.

Generalizes the GitHub API filter into a YAML-driven request inspector.
Rules are loaded from YAML files, compiled with pre-compiled regex patterns,
and evaluated in priority order (deny wins over allow on ties).
"""

from __future__ import annotations

import importlib.resources
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

import yaml

from .schemas.foundry_yaml import (
    DeepPolicyConfig,
    DeepPolicyRule,
    DeepPolicyServiceConfig,
)

logger = logging.getLogger(__name__)

_BUNDLED_SCHEME = "bundled://"

# Map of bundled:// names to file basenames
_BUNDLED_POLICIES = {
    "github-default": "github",
}


class CompiledRule:
    """A DeepPolicyRule with pre-compiled regex patterns."""

    __slots__ = (
        "action", "body_jsonpath", "body_pattern_compiled", "body_value",
        "condition", "host", "method", "path_compiled", "priority", "reason",
    )

    def __init__(self, rule: DeepPolicyRule) -> None:
        self.host = rule.host
        self.method = rule.method.upper() if rule.method != "*" else "*"
        self.path_compiled = re.compile(rule.path_pattern)
        self.body_jsonpath = rule.body_jsonpath
        self.body_value = rule.body_value
        self.body_pattern_compiled = (
            re.compile(rule.body_pattern) if rule.body_pattern else None
        )
        self.action = rule.action
        self.reason = rule.reason
        self.priority = rule.priority
        self.condition = rule.condition


def _traverse_jsonpath(data: dict[str, Any], path: str) -> Any:
    """Walk a dot-notation path into a JSON dict tree.

    Returns None if any segment is missing or the intermediate value
    is not a dict.
    """
    if not path:
        return None
    current: Any = data
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def _match_body(actual: Any, rule: CompiledRule) -> bool:
    """Check if a body value matches a compiled rule's body constraints."""
    if not rule.body_jsonpath:
        return True  # no body check required

    if actual is None:
        return False  # jsonpath didn't resolve

    if rule.body_value:
        return str(actual) == rule.body_value

    if rule.body_pattern_compiled:
        return bool(rule.body_pattern_compiled.search(str(actual)))

    return True  # jsonpath resolved to any truthy value


def _check_condition(condition: str, context: dict[str, Any]) -> bool:
    """Evaluate a simple 'key == value' or 'key != value' condition."""
    if not condition:
        return True

    for op in (" == ", " != "):
        if op in condition:
            key, value = condition.split(op, 1)
            key = key.strip()
            value = value.strip()
            ctx_value = str(context.get(key, ""))
            if op.strip() == "==":
                return ctx_value == value
            return ctx_value != value

    return True


def _strip_graphql_comments(query: str) -> str:
    """Remove # comments from a GraphQL query, respecting string literals."""
    result: list[str] = []
    i = 0
    in_triple = False
    in_single = False
    while i < len(query):
        if not in_triple and not in_single:
            if query[i:i + 3] == '"""':
                in_triple = True
                result.append(query[i:i + 3])
                i += 3
                continue
            if query[i] == '"':
                in_single = True
                result.append(query[i])
                i += 1
                continue
            if query[i] == '#':
                while i < len(query) and query[i] != '\n':
                    i += 1
                continue
        elif in_triple:
            if query[i:i + 4] == '\\"""':
                result.append(query[i:i + 4])
                i += 4
                continue
            if query[i:i + 3] == '"""':
                in_triple = False
                result.append(query[i:i + 3])
                i += 3
                continue
        elif in_single:
            if query[i] == '\\':
                result.append(query[i])
                if i + 1 < len(query):
                    result.append(query[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if query[i] == '"':
                in_single = False
                result.append(query[i])
                i += 1
                continue
        result.append(query[i])
        i += 1
    return "".join(result)


class PolicySet:
    """Compiled set of rules for a single service slug."""

    def __init__(
        self,
        slug: str,
        service_config: DeepPolicyServiceConfig,
    ) -> None:
        self.slug = slug
        self.host = service_config.host
        self.scheme = service_config.scheme
        self.port = service_config.port
        self.default_action = service_config.default_action

        self._rules: list[CompiledRule] = []
        for r in service_config.rules:
            self._rules.append(CompiledRule(r))

        # Sort: highest priority first, deny wins on ties (deny gets higher secondary key)
        self._rules.sort(
            key=lambda r: (r.priority, 1 if r.action == "deny" else 0),
            reverse=True,
        )

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def evaluate(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None]:
        """Evaluate rules against a request.

        Args:
            method: HTTP method.
            path: URL path (query string stripped).
            body: Request body bytes.
            context: Evaluation context for conditional rules
                     (e.g. {"allow_pr_operations": "false"}).

        Returns:
            (allowed, reason) where reason is None if allowed.
        """
        method = method.upper()
        path_no_query = path.split("?")[0]
        ctx = context or {}

        # Parse body for jsonpath checks
        body_data: dict[str, Any] | None = None
        if body:
            try:
                body_data = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                body_data = None

        # If this is a GraphQL request, strip comments from the query
        if body_data and method == "POST" and path_no_query == "/graphql":
            query = body_data.get("query", "")
            if isinstance(query, str):
                body_data["query"] = _strip_graphql_comments(query)

        for rule in self._rules:
            # Check condition
            if not _check_condition(rule.condition, ctx):
                continue

            # Check method
            if rule.method != "*" and rule.method != method:
                continue

            # Check path
            if not rule.path_compiled.match(path_no_query):
                continue

            # Check body
            if rule.body_jsonpath:
                if body is None:
                    # No body provided — body condition can't be met, skip rule
                    continue

                if body_data is None:
                    # Body exists but unparseable — fail closed on deny rules
                    if rule.action == "deny":
                        return False, rule.reason or "Request blocked (unparseable body)"
                    continue

                actual = _traverse_jsonpath(body_data, rule.body_jsonpath)
                if actual is None:
                    continue

                if not _match_body(actual, rule):
                    continue

            # Rule matches
            if rule.action == "deny":
                return False, rule.reason or "Request denied by policy"
            return True, None

        # No rule matched — apply default_action
        if self.default_action == "allow":
            return True, None
        return False, f"Request denied by default policy ({method} {path_no_query})"


class CircuitBreaker:
    """Per-service-slug circuit breaker with three states.

    closed -> open (after threshold consecutive failures)
    open -> half-open (after recovery_seconds)
    half-open -> closed (on success) or open (on failure)
    """

    def __init__(
        self,
        threshold: int = 5,
        recovery_seconds: int = 30,
    ) -> None:
        self._threshold = threshold
        self._recovery_seconds = recovery_seconds
        self._lock = threading.Lock()
        self._states: dict[str, dict[str, Any]] = {}

    def _get_state(self, slug: str) -> dict[str, Any]:
        if slug not in self._states:
            self._states[slug] = {
                "state": "closed",
                "failures": 0,
                "opened_at": 0.0,
            }
        return self._states[slug]

    def record_success(self, slug: str) -> None:
        with self._lock:
            entry = self._get_state(slug)
            entry["state"] = "closed"
            entry["failures"] = 0

    def record_failure(self, slug: str) -> None:
        with self._lock:
            entry = self._get_state(slug)
            if entry["state"] == "half-open":
                entry["state"] = "open"
                entry["opened_at"] = time.monotonic()
                return
            entry["failures"] += 1
            if entry["failures"] >= self._threshold:
                entry["state"] = "open"
                entry["opened_at"] = time.monotonic()

    def is_open(self, slug: str) -> bool:
        with self._lock:
            entry = self._get_state(slug)
            if entry["state"] == "closed":
                return False
            if entry["state"] == "open":
                elapsed = time.monotonic() - entry["opened_at"]
                if elapsed >= self._recovery_seconds:
                    entry["state"] = "half-open"
                    return False
                return True
            # half-open: allow one probe
            return False

    def get_state(self, slug: str) -> str:
        with self._lock:
            return self._get_state(slug)["state"]


def _load_bundled_policy(name: str) -> dict[str, Any]:
    """Load a bundled policy YAML from the default_config package."""
    basename = _BUNDLED_POLICIES.get(name, name)
    resource_name = f"deep-policy-{basename}.yaml"
    try:
        ref = importlib.resources.files(
            "foundry_git_safety.default_config"
        ).joinpath(resource_name)
        data = ref.read_text(encoding="utf-8")
        return yaml.safe_load(data)  # type: ignore[no-any-return]
    except (FileNotFoundError, TypeError):
        raise FileNotFoundError(f"Bundled policy '{name}' not found")


def _load_policy_file(path: str) -> dict[str, Any]:
    """Load a policy YAML from a file path or bundled:// URI."""
    if path.startswith(_BUNDLED_SCHEME):
        name = path[len(_BUNDLED_SCHEME):]
        return _load_bundled_policy(name)

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    data = p.read_text(encoding="utf-8")
    return yaml.safe_load(data)  # type: ignore[no-any-return]


def _parse_policy_yaml(
    raw: dict[str, Any],
) -> dict[str, DeepPolicyServiceConfig]:
    """Parse a policy YAML dict into service configs."""
    services: dict[str, DeepPolicyServiceConfig] = {}
    for svc_data in raw.get("services", []):
        rules = [DeepPolicyRule(**r) for r in svc_data.get("rules", [])]
        svc = DeepPolicyServiceConfig(
            slug=svc_data["slug"],
            host=svc_data.get("host", ""),
            scheme=svc_data.get("scheme", "https"),
            port=svc_data.get("port", 0),
            rules=rules,
            default_action=svc_data.get("default_action", "deny"),
        )
        services[svc.slug] = svc
    return services


def load_policy_sets(
    config: DeepPolicyConfig,
) -> tuple[dict[str, PolicySet], dict[str, DeepPolicyServiceConfig]]:
    """Load all policy sets from config.

    Returns:
        Tuple of (policy_sets dict, service_configs dict) keyed by slug.
    """
    all_services: dict[str, DeepPolicyServiceConfig] = {}

    # Load from top-level policy_file
    if config.policy_file:
        try:
            raw = _load_policy_file(config.policy_file)
            all_services.update(_parse_policy_yaml(raw))
        except Exception as exc:
            logger.error("Failed to load policy file %s: %s", config.policy_file, exc)

    # Load from individual service policy_files (override/extend)
    for svc_cfg in config.services:
        if svc_cfg.policy_file:
            try:
                raw = _load_policy_file(svc_cfg.policy_file)
                file_services = _parse_policy_yaml(raw)
                if svc_cfg.slug in file_services:
                    # Merge inline rules on top of file rules
                    merged = file_services[svc_cfg.slug]
                    merged.rules = list(merged.rules) + list(svc_cfg.rules)
                    all_services[svc_cfg.slug] = merged
                else:
                    all_services[svc_cfg.slug] = svc_cfg
            except Exception as exc:
                logger.error(
                    "Failed to load service policy %s: %s",
                    svc_cfg.policy_file, exc,
                )
                all_services[svc_cfg.slug] = svc_cfg
        else:
            all_services[svc_cfg.slug] = svc_cfg

    # Compile policy sets
    policy_sets: dict[str, PolicySet] = {}
    for slug, svc in all_services.items():
        policy_sets[slug] = PolicySet(slug=slug, service_config=svc)

    return policy_sets, all_services
