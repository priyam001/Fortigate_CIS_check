"""
CIS Benchmark Rule Base Classes
=================================
Defines the base rule structure, result types, and severity/level enums
used by every CIS FortiGate 7.4.x Benchmark v1.0.1 control.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)


class CISLevel(Enum):
    """CIS Benchmark profile applicability."""
    LEVEL_1 = 1  # Basic security settings applicable to most organizations
    LEVEL_2 = 2  # Advanced settings for high-security environments


class AssessmentStatus(Enum):
    """How CIS classifies the recommendation's audit procedure."""
    AUTOMATED = "Automated"
    MANUAL = "Manual"


class RuleStatus(Enum):
    """
    Outcome of evaluating a rule against a configuration.

    PASS / FAIL are only produced for controls CIS marks "Automated" and that
    this tool can fully verify from the configuration file alone. Controls
    CIS marks "Manual" (or automated controls that need information outside
    the config, such as physical security or firmware-release currency)
    resolve to MANUAL_REVIEW instead of a guessed PASS/FAIL, so results never
    imply more certainty than the underlying evidence supports.
    """
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ERROR = "ERROR"


class RuleSeverity(Enum):
    """Risk severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @property
    def weight(self) -> int:
        weights = {
            "Critical": 10,
            "High": 7,
            "Medium": 4,
            "Low": 1,
        }
        return weights.get(self.value, 1)

    @property
    def color(self) -> str:
        colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
        }
        return colors.get(self.value, "#6c757d")


@dataclass
class RuleResult:
    """Result of evaluating a single CIS control against a configuration."""
    rule_id: str
    title: str
    level: CISLevel
    severity: RuleSeverity
    status: RuleStatus
    description: str
    expected_value: str
    actual_value: str
    remediation: str
    assessment_status: AssessmentStatus = AssessmentStatus.AUTOMATED
    category: str = ""
    cis_section: str = ""
    remediation_cli: str = ""
    evidence: str = ""
    rationale: str = ""
    references: List[str] = field(default_factory=list)
    notes: str = ""  # free-text annotation the user can attach (e.g. via the web UI); carried into every generated report

    @property
    def passed(self) -> bool:
        return self.status == RuleStatus.PASS

    @property
    def failed(self) -> bool:
        return self.status == RuleStatus.FAIL

    @property
    def manual_review(self) -> bool:
        return self.status == RuleStatus.MANUAL_REVIEW

    @property
    def status_value(self) -> str:
        return self.status.value

    @property
    def severity_value(self) -> str:
        return self.severity.value

    @property
    def level_value(self) -> int:
        return self.level.value

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "assessment_status": self.assessment_status.value,
            "passed": self.passed,
            "manual_review": self.manual_review,
            "description": self.description,
            "rationale": self.rationale,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "remediation_cli": self.remediation_cli,
            "category": self.category,
            "cis_section": self.cis_section,
            "references": self.references,
            "notes": self.notes,
        }


class CISRule:
    """
    Base class for CIS Benchmark controls.

    `assessment_status` mirrors CIS's own "Automated"/"Manual" classification
    for the recommendation. Rules whose CIS classification is MANUAL should
    always resolve to RuleStatus.MANUAL_REVIEW from evaluate() (never guess
    PASS/FAIL); rules classified AUTOMATED may still fall back to
    MANUAL_REVIEW when the configuration file does not contain enough
    information to make a reliable determination.
    """

    def __init__(
        self,
        rule_id: str,
        title: str,
        level: CISLevel,
        severity: RuleSeverity,
        description: str,
        expected_value: str,
        remediation: str,
        assessment_status: AssessmentStatus = AssessmentStatus.AUTOMATED,
        category: str = "",
        cis_section: str = "",
        remediation_cli: str = "",
        rationale: str = "",
        references: Optional[List[str]] = None,
    ):
        self.rule_id = rule_id
        self.title = title
        self.level = level
        self.severity = severity
        self.description = description
        self.expected_value = expected_value
        self.remediation = remediation
        self.assessment_status = assessment_status
        self.category = category
        self.cis_section = cis_section
        self.remediation_cli = remediation_cli
        self.rationale = rationale
        self.references = references or []

    def evaluate(self, config) -> RuleResult:
        """
        Evaluate this rule against a FortiGateConfig.
        Must be overridden in subclasses or use the factory pattern.
        """
        raise NotImplementedError("Subclasses must implement evaluate()")

    def _make_result(
        self,
        status: RuleStatus,
        actual_value: str,
        evidence: str = "",
    ) -> RuleResult:
        """Helper to create a RuleResult with this rule's metadata."""
        if status == RuleStatus.PASS:
            remediation = "No action needed"
            remediation_cli = ""
        elif status == RuleStatus.MANUAL_REVIEW:
            remediation = self.remediation
            remediation_cli = self.remediation_cli
        else:
            remediation = self.remediation
            remediation_cli = self.remediation_cli

        return RuleResult(
            rule_id=self.rule_id,
            title=self.title,
            level=self.level,
            severity=self.severity,
            status=status,
            assessment_status=self.assessment_status,
            description=self.description,
            rationale=self.rationale,
            expected_value=self.expected_value,
            actual_value=actual_value,
            evidence=evidence,
            remediation=remediation,
            category=self.category,
            cis_section=self.cis_section,
            remediation_cli=remediation_cli,
            references=self.references,
        )

    def _pass(self, actual_value: str, evidence: str = "") -> RuleResult:
        return self._make_result(RuleStatus.PASS, actual_value, evidence)

    def _fail(self, actual_value: str, evidence: str = "") -> RuleResult:
        return self._make_result(RuleStatus.FAIL, actual_value, evidence)

    def _manual(self, actual_value: str, evidence: str = "") -> RuleResult:
        return self._make_result(RuleStatus.MANUAL_REVIEW, actual_value, evidence)


class CallableCISRule(CISRule):
    """
    A CIS rule that uses a callable evaluator function.
    This avoids needing a separate class for each rule.
    """

    def __init__(self, evaluator_fn, **kwargs):
        super().__init__(**kwargs)
        self._evaluator = evaluator_fn

    def evaluate(self, config) -> RuleResult:
        try:
            return self._evaluator(self, config)
        except Exception as e:
            logger.error(f"Rule {self.rule_id} evaluation failed: {e}")
            return RuleResult(
                rule_id=self.rule_id,
                title=self.title,
                level=self.level,
                severity=self.severity,
                status=RuleStatus.ERROR,
                assessment_status=self.assessment_status,
                description=self.description,
                rationale=self.rationale,
                expected_value=self.expected_value,
                actual_value=f"Evaluation error: {e}",
                remediation=self.remediation,
                category=self.category,
                cis_section=self.cis_section,
                remediation_cli=self.remediation_cli,
                references=self.references,
            )
