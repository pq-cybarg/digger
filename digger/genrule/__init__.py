"""Generate portable detection rules from digger findings.

The point: close the IR-to-detection-engineering feedback loop. A
finding represents "we noticed something on this host now"; a generated
rule represents "any host running this rule will notice the same thing
in the future." Auto-mapping findings to portable rule formats means a
junior analyst's investigation produces a fleet-wide detection at
zero marginal effort.

Currently emits:
  * **Sigma YAML** — portable detection logic consumed by Splunk,
    Elastic, Sentinel, Chronicle, etc. via sigma-cli / pysigma.

Future emitters could include CACAO playbooks (for SOAR consumption)
and YARA rules (for findings whose evidence carries enough binary
context).
"""

from digger.genrule.sigma import (
    finding_to_sigma,
    generate_detector_templates,
    generate_sigma_rules,
    write_sigma_rules,
)

__all__ = [
    "finding_to_sigma", "generate_sigma_rules",
    "generate_detector_templates", "write_sigma_rules",
]
