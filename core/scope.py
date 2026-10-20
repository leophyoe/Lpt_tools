"""Scope authorization and target validation service.

Enforces strict boundaries before any network scan or assessment tool
is allowed to execute against an IP, CIDR subnet, or hostname.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

from storage.models import TargetScope, TargetType


@dataclass
class ScopeCheckResult:
    is_allowed: bool
    reason: str
    matched_scope: Optional[TargetScope] = None


class ScopeAuthorizationService:
    """Validates targets against project authorization scopes."""

    @staticmethod
    def _extract_host_or_ip(raw_target: str) -> str:
        """Clean and extract host or IP from URLs or host:port strings."""
        target = raw_target.strip()
        if "://" in target:
            parsed = urlparse(target)
            target = parsed.hostname or target
        elif ":" in target and not target.endswith("]"):  # Avoid IPv6 [::1]:80 issues
            target = target.split(":")[0]
        return target

    @classmethod
    def is_target_authorized(
        cls,
        target: str,
        scopes: List[TargetScope],
    ) -> ScopeCheckResult:
        """Verify if a target IP, CIDR, or hostname is authorized by project scopes."""
        if not scopes:
            return ScopeCheckResult(
                is_allowed=False,
                reason="No authorized target scopes defined for this project.",
            )

        clean_target = cls._extract_host_or_ip(target)

        # Check if the target is an IP address
        try:
            target_ip = ipaddress.ip_address(clean_target)
            is_ip = True
        except ValueError:
            target_ip = None
            is_ip = False

        for scope in scopes:
            if not scope.is_authorized:
                continue

            scope_clean = cls._extract_host_or_ip(scope.target)

            # 1. Match IP or CIDR network
            if is_ip:
                try:
                    # Is scope a CIDR network?
                    scope_net = ipaddress.ip_network(scope_clean, strict=False)
                    if target_ip in scope_net:
                        return ScopeCheckResult(
                            is_allowed=True,
                            reason=f"Target {clean_target} falls within authorized network {scope.target}.",
                            matched_scope=scope,
                        )
                except ValueError:
                    # Scope might be a hostname or invalid network
                    pass

            # 2. Match exact hostname or wildcard domain
            if not is_ip:
                if clean_target.lower() == scope_clean.lower():
                    return ScopeCheckResult(
                        is_allowed=True,
                        reason=f"Target {clean_target} matches authorized host {scope.target}.",
                        matched_scope=scope,
                    )
                # Wildcard support, e.g. *.example.com or .example.com
                if scope_clean.startswith("*."):
                    domain_suffix = scope_clean[1:].lower()
                    if clean_target.lower().endswith(domain_suffix):
                        return ScopeCheckResult(
                            is_allowed=True,
                            reason=f"Target {clean_target} matches domain pattern {scope.target}.",
                            matched_scope=scope,
                        )

        return ScopeCheckResult(
            is_allowed=False,
            reason=f"Target '{clean_target}' is NOT in the authorized scope list.",
        )
