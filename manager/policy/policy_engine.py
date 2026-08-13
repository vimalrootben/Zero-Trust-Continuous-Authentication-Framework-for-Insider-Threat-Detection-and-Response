"""
PolicyEngine — Real-time security policy evaluation, risk scoring, alert generation, and response dispatch.

Flow:
  Telemetry Event -> Collector -> Transport -> PolicyEngine -> ConditionEvaluator
  -> Policy Match -> Risk Delta -> Alert Generation -> Endpoint Response Execution / Command -> Audit Log -> DB Status
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.rules.conditions import ConditionEvaluator
from manager.rules.rule_loader import RuleDTO, RuleLoader
from manager.database.models.policy import Policy as PolicyModel
from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.audit import AuditLog, ActorType
from agent.responses.response_handler import AgentResponseHandler, ResponseExecutionResult

logger = logging.getLogger(__name__)


class PolicyEvaluationResult:
    """Represents the evaluation outcome for a single policy match."""

    def __init__(
        self,
        policy_code: str,
        name: str,
        category: str,
        severity: str,
        score_impact: int,
        mitre_technique_id: Optional[str] = None,
        action: Optional[str] = None,
        mode: str = "ALERT_ONLY",
        execution_result: Optional[ResponseExecutionResult] = None,
        alert_id: Optional[uuid.UUID] = None,
    ):
        self.policy_code = policy_code
        self.name = name
        self.category = category
        self.severity = severity
        self.score_impact = score_impact
        self.mitre_technique_id = mitre_technique_id
        self.action = action
        self.mode = mode
        self.execution_result = execution_result
        self.alert_id = alert_id
        self.evaluated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_code": self.policy_code,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "score_impact": self.score_impact,
            "mitre_technique_id": self.mitre_technique_id,
            "action": self.action,
            "mode": self.mode,
            "execution_result": self.execution_result.to_dict() if self.execution_result else None,
            "alert_id": str(self.alert_id) if self.alert_id else None,
            "evaluated_at": self.evaluated_at,
        }


class PolicyEngine:
    """Core Zero Trust Policy Engine."""

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        risk_engine: Optional[Any] = None,
        alert_service: Optional[Any] = None,
        db_session: Optional[AsyncSession] = None,
    ):
        self.rules_dir = rules_dir
        self.risk_engine = risk_engine
        self.alert_service = alert_service
        self.db_session = db_session
        self.loader = RuleLoader()
        self.evaluator = ConditionEvaluator()
        self.response_handler = AgentResponseHandler(mode="ENFORCE")
        self._policies_cache: List[RuleDTO] = []

        if self.rules_dir:
            self.reload_policies()

    def reload_policies(self, override_policies: Optional[List[RuleDTO]] = None) -> None:
        """Reload in-memory policy cache from rules directory or explicit list."""
        if override_policies is not None:
            self._policies_cache = override_policies
        elif self.rules_dir:
            self._policies_cache = self.loader.load_rules_from_files(self.rules_dir)
        else:
            self._policies_cache = []

        logger.info(f"PolicyEngine reloaded with {len(self._policies_cache)} policies.")

    def add_policy(self, policy: RuleDTO) -> None:
        """Add a policy to in-memory active cache."""
        self._policies_cache.append(policy)

    def evaluate_event(
        self,
        event_data: Dict[str, Any],
        agent_id: Optional[str] = None,
        db_session: Optional[AsyncSession] = None,
        mode_override: Optional[str] = None,
    ) -> List[PolicyEvaluationResult]:
        """
        Evaluate normalized telemetry event_data against all active policies.

        Executes the real policy pipeline:
          1. Condition Evaluation
          2. Risk Delta Impact Calculation
          3. Alert Generation
          4. Agent Response Action Execution (OBSERVE, ALERT_ONLY, DRY_RUN, ENFORCE)
          5. Audit Record
        """
        results: List[PolicyEvaluationResult] = []

        for policy in self._policies_cache:
            if not policy.enabled:
                continue

            try:
                if self.evaluator.evaluate(policy.condition, event_data):
                    logger.info(
                        f"Policy MATCH: {policy.rule_code} ('{policy.name}') on agent {agent_id}"
                    )

                    # 1. Risk Engine integration
                    if self.risk_engine and agent_id and hasattr(self.risk_engine, "apply_delta"):
                        try:
                            self.risk_engine.apply_delta(
                                agent_id=agent_id,
                                delta=policy.score_impact,
                                reason=f"Matched policy {policy.rule_code}: {policy.name}",
                                rule_id=policy.rule_id or policy.rule_code,
                            )
                        except Exception as e:
                            logger.error(f"Error applying risk delta for policy {policy.rule_code}: {e}")

                    # 2. Alert creation
                    alert_id = None
                    if self.alert_service and hasattr(self.alert_service, "create_alert"):
                        try:
                            alert = self.alert_service.create_alert(
                                agent_id=agent_id,
                                title=policy.name,
                                description=f"Policy {policy.rule_code} matched telemetry event.",
                                severity=policy.severity,
                                mitre_technique_id=policy.mitre_technique_id,
                            )
                            if alert and hasattr(alert, "id"):
                                alert_id = alert.id
                        except Exception as e:
                            logger.error(f"Error creating alert for policy {policy.rule_code}: {e}")

                    # 3. Real Agent Response Execution
                    action_name = policy.response_action or "ALERT"
                    execution_res = None
                    effective_mode = mode_override or getattr(policy, "mode", "ALERT_ONLY")
                    if action_name and action_name != "ALERT":
                        params = {
                            "agent_id": agent_id,
                            "policy_code": policy.rule_code,
                            "process_name": event_data.get("data", {}).get("process_name"),
                            "pid": event_data.get("data", {}).get("pid"),
                            "file_path": event_data.get("data", {}).get("file_path"),
                            "remote_ip": event_data.get("data", {}).get("remote_ip"),
                            "remote_port": event_data.get("data", {}).get("remote_port"),
                        }
                        execution_res = self.response_handler.execute_action(
                            action=action_name,
                            params=params,
                            mode_override=effective_mode,
                        )

                    eval_res = PolicyEvaluationResult(
                        policy_code=policy.rule_code,
                        name=policy.name,
                        category=policy.category,
                        severity=policy.severity,
                        score_impact=policy.score_impact,
                        mitre_technique_id=policy.mitre_technique_id,
                        action=action_name,
                        mode=effective_mode,
                        execution_result=execution_res,
                        alert_id=alert_id,
                    )
                    results.append(eval_res)

            except Exception as exc:
                logger.error(f"Error evaluating policy {policy.rule_code}: {exc}")
                continue

        return results
