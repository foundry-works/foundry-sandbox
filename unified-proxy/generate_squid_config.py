#!/usr/bin/env python3
"""Generate Squid domain list files from allowlist.yaml.

Reads the unified proxy allowlist configuration and generates two files
consumed by Squid ACLs at runtime:

  /etc/squid/allowed_domains.txt  — all allowed domains (Squid dstdomain format)
  /etc/squid/mitm_domains.txt     — domains requiring MITM credential injection

Squid dstdomain format:
  - "example.com"    → exact match
  - ".example.com"   → matches example.com and all subdomains (*.example.com)

Usage:
  python3 generate_squid_config.py [--output-dir /etc/squid]
"""

import argparse
import os
import sys

# Ensure /opt/proxy is on sys.path so imports work inside the container
_PROXY_DIR = "/opt/proxy"
if _PROXY_DIR not in sys.path:
    sys.path.insert(0, _PROXY_DIR)

from config import load_allowlist_config  # noqa: E402
from logging_config import get_logger  # noqa: E402

logger = get_logger(__name__)

# MITM-required domains: providers that still need mitmproxy for credential
# injection (from credential_injector.py PROVIDER_MAP + OAuth endpoints).
#
# SYNC WARNING: This list must stay in sync with PROVIDER_MAP in
# addons/credential_injector.py.  If you add a new MITM provider there,
# add its domain(s) here too so Squid routes them through mitmproxy.
MITM_DOMAINS = [
    # Gemini / Google AI
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudcode-pa.googleapis.com",
    # Tavily
    "api.tavily.com",
    # Semantic Scholar
    "api.semanticscholar.org",
    # Perplexity
    "api.perplexity.ai",
    # Zhipu AI
    "api.z.ai",
    "open.bigmodel.cn",
    # GitHub (uploads + main site for git credential injection)
    "uploads.github.com",
    "github.com",
    # OAuth endpoints
    "auth.openai.com",
    "oauth2.googleapis.com",
    "accounts.google.com",
    # ChatGPT / Codex (OAuth flow)
    "chatgpt.com",
]


def _to_squid_domain(domain: str) -> str:
    """Convert an allowlist domain pattern to Squid dstdomain format.

    Args:
        domain: Domain from allowlist.yaml, e.g. "example.com" or "*.example.com"

    Returns:
        Squid dstdomain format string.
    """
    if domain.startswith("*."):
        # "*.example.com" → ".example.com" (Squid subdomain match)
        return domain[1:]  # strip leading "*", keep the dot
    return domain


def generate_squid_config(output_dir: str = "/etc/squid") -> None:
    """Generate Squid domain files from allowlist.yaml.

    Args:
        output_dir: Directory to write the domain list files.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Load the allowlist configuration
    config = load_allowlist_config()

    # Build allowed domains set (all domains from allowlist.yaml)
    allowed_domains: list[str] = []
    seen: set[str] = set()
    for domain in config.domains:
        squid_domain = _to_squid_domain(domain)
        if squid_domain not in seen:
            allowed_domains.append(squid_domain)
            seen.add(squid_domain)

    # Build MITM domains set (subset that needs credential injection)
    mitm_domains: list[str] = []
    mitm_seen: set[str] = set()
    for domain in MITM_DOMAINS:
        squid_domain = _to_squid_domain(domain)
        if squid_domain not in mitm_seen:
            mitm_domains.append(squid_domain)
            mitm_seen.add(squid_domain)
            # Ensure MITM domains are also in the allowed list
            if squid_domain not in seen:
                allowed_domains.append(squid_domain)
                seen.add(squid_domain)

    # Write allowed domains file
    allowed_path = os.path.join(output_dir, "allowed_domains.txt")
    with open(allowed_path, "w") as f:
        for domain in sorted(allowed_domains):
            f.write(domain + "\n")
    logger.info(
        f"Wrote {len(allowed_domains)} allowed domains to {allowed_path}"
    )

    # Write MITM domains file
    mitm_path = os.path.join(output_dir, "mitm_domains.txt")
    with open(mitm_path, "w") as f:
        for domain in sorted(mitm_domains):
            f.write(domain + "\n")
    logger.info(
        f"Wrote {len(mitm_domains)} MITM domains to {mitm_path}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate Squid domain list files from allowlist.yaml"
    )
    parser.add_argument(
        "--output-dir",
        default="/etc/squid",
        help="Directory to write domain list files (default: /etc/squid)",
    )
    args = parser.parse_args()

    generate_squid_config(output_dir=args.output_dir)


if __name__ == "__main__":
    main()
