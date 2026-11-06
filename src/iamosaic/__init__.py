"""IAMosaic: offline cloud-IAM policy review.

Public API
----------
``analyze_policy``   report over-permission grants in an exported policy
``policy_edges``     permission-relationship edges for visualization
``policy_version``   the ``Version`` declared by the policy, when present
"""
from .analyzer import (
    RULE_CG001,
    RULE_CG002,
    RULE_CG003,
    analyze_policy,
    policy_edges,
    policy_version,
)

__all__ = [
    "RULE_CG001",
    "RULE_CG002",
    "RULE_CG003",
    "__version__",
    "analyze_policy",
    "policy_edges",
    "policy_version",
]

__version__ = "0.2.0"
