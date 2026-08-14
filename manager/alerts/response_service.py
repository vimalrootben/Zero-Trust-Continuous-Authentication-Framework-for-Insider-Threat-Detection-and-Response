import logging
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from manager.database.models.alert import Alert, AlertStatus
from manager.database.models.alert_response import AlertResponse, AlertResponseStatus, AlertResponseAction
from manager.database.models.command import Command, CommandStatus
from manager.database.models.agent import Agent
from manager.audit.audit_logger import AuditLogger
from manager.audit.constants import AuditAction
from manager.websocket.command_dispatcher import CommandDispatcher

logger = logging.getLogger(__name__)

ACTION_COMMAND_MAP = {
    AlertResponseAction.PROCESS_TERMINATE.value: "KILL_PROCESS",
    AlertResponseAction.NETWORK_ISOLATE.value: "DISABLE_NETWORK",
    AlertResponseAction.NETWORK_UNISOLATE.value: "ENABLE_NETWORK",
    AlertResponseAction.USER_LOGOUT.value: "LOGOFF_USER",
    AlertResponseAction.WORKSTATION_LOCK.value: "LOCK_WORKSTATION",
    AlertResponseAction.FILE_QUARANTINE.value: "QUARANTINE_FILE",
}

ACTIVE_RESPONSE_STATES = {
    AlertResponseStatus.PENDING,
    AlertResponseStatus.AUTHORIZED,
    AlertResponseStatus.DISPATCHED,
    AlertResponseStatus.EXECUTING,
}

class ResponseService:
    """Service handling response action requests, authorization, command signing, agent dispatching, and result tracking."""

    def __init__(
        self,
        db_session: AsyncSession,
        audit_logger: Optional[AuditLogger] = None,
        ws_manager: Optional[Any] = None
    ):
        self.db = db_session
        self.audit_logger = audit_logger or AuditLogger(db_session)
        self.ws_manager = ws_manager

    async def execute_response(
        self,
        alert_id: uuid.UUID,
        action: str,
        user_id: uuid.UUID,
        params: Optional[Dict[str, Any]] = None
    ) -> AlertResponse:
        """
        Validates request, checks idempotency, creates AlertResponse, creates signed Command,
        updates Alert state, and dispatches command to Agent via WebSocket.
        """
        params = params or {}
        now = datetime.now(timezone.utc)

        # 1. Fetch & validate Alert
        res = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        alert = res.scalar_one_or_none()
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")

        if alert.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            raise ValueError(f"Cannot execute response action on an alert in '{alert.status.value}' state")

        # 2. Fetch & validate Agent
        agent_res = await self.db.execute(select(Agent).where(Agent.id == alert.agent_id))
        agent = agent_res.scalar_one_or_none()
        if not agent:
            raise ValueError(f"Target agent {alert.agent_id} not found")

        # 3. Idempotency Check: Prevent duplicate concurrent execution
        active_res = await self.db.execute(
            select(AlertResponse).where(
                AlertResponse.alert_id == alert_id,
                AlertResponse.action == action,
                AlertResponse.status.in_(ACTIVE_RESPONSE_STATES)
            )
        )
        if active_res.scalar_one_or_none():
            raise ValueError(f"Response action '{action}' is already active/executing on alert {alert_id}")

        # 4. Action Parameter Validation
        command_type = ACTION_COMMAND_MAP.get(action)
        if not command_type:
            raise ValueError(f"Unsupported response action: '{action}'")

        command_params = self._build_command_params(action, alert, params)

        # 5. Create AlertResponse (Status: PENDING -> AUTHORIZED)
        corr_id = alert.correlation_id or f"CORR-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
        resp_row = AlertResponse(
            alert_id=alert.id,
            agent_id=alert.agent_id,
            action=action,
            status=AlertResponseStatus.AUTHORIZED,
            requested_by=user_id,
            authorized_by=user_id,
            correlation_id=corr_id,
            requested_at=now,
            started_at=now
        )
        self.db.add(resp_row)
        await self.db.flush()

        # Audit RESPONSE_REQUESTED & RESPONSE_AUTHORIZED
        await self.audit_logger.log(
            actor_type="user",
            actor_id=user_id,
            action=AuditAction.RESPONSE_REQUESTED,
            target_type="alert",
            target_id=alert.id,
            details={"action": action, "response_id": str(resp_row.id)},
            db_session=self.db
        )
        await self.audit_logger.log(
            actor_type="user",
            actor_id=user_id,
            action=AuditAction.RESPONSE_AUTHORIZED,
            target_type="alert",
            target_id=alert.id,
            details={"action": action, "response_id": str(resp_row.id)},
            db_session=self.db
        )

        # 6. Create Signed Command
        cmd_id = uuid.uuid4()
        payload_str = f"{cmd_id}:{command_type}:{alert.agent_id}:{now.isoformat()}"
        signature = hashlib.sha256(payload_str.encode()).hexdigest()

        cmd_row = Command(
            id=cmd_id,
            agent_id=alert.agent_id,
            command_type=command_type,
            payload_json=command_params,
            issued_by=user_id,
            policy_id=alert.policy_id,
            signature=signature,
            status=CommandStatus.PENDING,
            issued_at=now
        )
        self.db.add(cmd_row)
        await self.db.flush()

        # Link command to AlertResponse
        resp_row.command_id = cmd_row.id
        resp_row.status = AlertResponseStatus.DISPATCHED

        # Update Alert lifecycle state & tracking fields
        alert.status = AlertStatus.RESPONSE_PENDING
        alert.response_status = AlertResponseStatus.DISPATCHED.value
        alert.response_action = action
        alert.response_requested_at = now
        alert.response_started_at = now

        await self.db.flush()

        # Audit RESPONSE_DISPATCHED
        await self.audit_logger.log(
            actor_type="system",
            actor_id=None,
            action=AuditAction.RESPONSE_DISPATCHED,
            target_type="agent",
            target_id=alert.agent_id,
            details={
                "response_id": str(resp_row.id),
                "command_id": str(cmd_id),
                "action": action,
                "command_type": command_type
            },
            db_session=self.db
        )

        # 7. Dispatch via WebSocket if manager reference is available
        pushed = False
        if self.ws_manager:
            dispatcher = CommandDispatcher(connection_manager=self.ws_manager, db_session=self.db)
            ws_payload = {
                "command_id": str(cmd_id),
                "command_type": command_type,
                "agent_id": str(alert.agent_id),
                "alert_id": str(alert.id),
                "response_id": str(resp_row.id),
                "params": command_params,
                "signature": signature,
                "issued_at": now.isoformat()
            }
            pushed = await dispatcher.dispatch(cmd_id, ws_payload, db_session=self.db)
            if pushed:
                resp_row.status = AlertResponseStatus.EXECUTING
                alert.status = AlertStatus.RESPONDING
                alert.response_status = AlertResponseStatus.EXECUTING.value
                await self.audit_logger.log(
                    actor_type="agent",
                    actor_id=alert.agent_id,
                    action=AuditAction.RESPONSE_STARTED,
                    target_type="alert",
                    target_id=alert.id,
                    details={"response_id": str(resp_row.id), "command_id": str(cmd_id)},
                    db_session=self.db
                )

        await self.db.commit()

        # Broadcast live status update to dashboards
        if self.ws_manager:
            try:
                await self.ws_manager.broadcast_alert_to_dashboards({
                    "type": "RESPONSE_STATUS_UPDATED",
                    "alert_id": str(alert.id),
                    "response_id": str(resp_row.id),
                    "action": action,
                    "status": resp_row.status.value
                })
            except Exception as exc:
                logger.error(f"Failed broadcasting response status update: {exc}")

        return resp_row

    async def handle_agent_result(
        self,
        command_id: uuid.UUID,
        success: bool,
        output: Optional[Dict[str, Any]] = None,
        error_msg: Optional[str] = None
    ) -> None:
        """Processes real execution result returned by Agent via WebSocket."""
        now = datetime.now(timezone.utc)
        output = output or {}

        # Fetch Command
        cmd = await self.db.get(Command, command_id)
        if not cmd:
            logger.warning(f"Command {command_id} not found during agent result processing")
            return

        cmd.status = CommandStatus.SUCCESS if success else CommandStatus.FAILED
        cmd.executed_at = now
        cmd.result_json = output

        # Fetch associated AlertResponse
        res = await self.db.execute(select(AlertResponse).where(AlertResponse.command_id == command_id))
        alert_resp = res.scalar_one_or_none()

        if alert_resp:
            alert_resp.completed_at = now
            alert_resp.result_json = output
            alert_resp.error_message = error_msg or output.get("message") if not success else None

            # Fetch Alert
            alert = await self.db.get(Alert, alert_resp.alert_id)
            if alert:
                alert.response_completed_at = now
                alert.response_result = output
                alert.response_error = alert_resp.error_message

                if success:
                    alert_resp.status = AlertResponseStatus.SUCCESS
                    alert.status = AlertStatus.RESOLVED
                    alert.response_status = AlertResponseStatus.SUCCESS.value
                    alert.resolved_at = now

                    # Update agent status if this was an isolation or unisolation action
                    agent = await self.db.get(Agent, alert.agent_id)
                    if agent:
                        if alert_resp.action in (AlertResponseAction.NETWORK_ISOLATE.value, "DISABLE_NETWORK", "ISOLATE_HOST"):
                            agent.status = AgentStatus.QUARANTINED
                            if self.ws_manager:
                                await self.ws_manager.broadcast_isolation_state(agent.id, "ISOLATED", output)
                                await self.ws_manager.broadcast_agent_status_change(agent.id, AgentStatus.QUARANTINED.value)
                        elif alert_resp.action in (AlertResponseAction.NETWORK_UNISOLATE.value, "ENABLE_NETWORK", "UNISOLATE_HOST"):
                            agent.status = AgentStatus.ACTIVE
                            if self.ws_manager:
                                await self.ws_manager.broadcast_isolation_state(agent.id, "NOT_ISOLATED", output)
                                await self.ws_manager.broadcast_agent_status_change(agent.id, AgentStatus.ACTIVE.value)

                    # Audit response success & specific isolation events
                    if alert_resp.action in (AlertResponseAction.NETWORK_ISOLATE.value, "DISABLE_NETWORK", "ISOLATE_HOST"):
                        await self.audit_logger.log(
                            actor_type="agent",
                            actor_id=alert.agent_id,
                            action=AuditAction.NETWORK_ISOLATION_SUCCEEDED,
                            target_type="agent",
                            target_id=alert.agent_id,
                            details={"response_id": str(alert_resp.id), "command_id": str(command_id), "result": output},
                            db_session=self.db
                        )
                    elif alert_resp.action in (AlertResponseAction.NETWORK_UNISOLATE.value, "ENABLE_NETWORK", "UNISOLATE_HOST"):
                        await self.audit_logger.log(
                            actor_type="agent",
                            actor_id=alert.agent_id,
                            action=AuditAction.NETWORK_UNISOLATION_SUCCEEDED,
                            target_type="agent",
                            target_id=alert.agent_id,
                            details={"response_id": str(alert_resp.id), "command_id": str(command_id), "result": output},
                            db_session=self.db
                        )

                    await self.audit_logger.log(
                        actor_type="agent",
                        actor_id=alert.agent_id,
                        action=AuditAction.RESPONSE_SUCCEEDED,
                        target_type="alert",
                        target_id=alert.id,
                        details={"response_id": str(alert_resp.id), "result": output},
                        db_session=self.db
                    )
                    await self.audit_logger.log(
                        actor_type="system",
                        actor_id=None,
                        action=AuditAction.ALERT_RESOLVED,
                        target_type="alert",
                        target_id=alert.id,
                        details={"resolution": "Resolved automatically by successful endpoint response"},
                        db_session=self.db
                    )
                else:
                    alert_resp.status = AlertResponseStatus.FAILED
                    alert.status = AlertStatus.RESPONSE_FAILED
                    alert.response_status = AlertResponseStatus.FAILED.value

                    if alert_resp.action in (AlertResponseAction.NETWORK_ISOLATE.value, "DISABLE_NETWORK", "ISOLATE_HOST"):
                        if self.ws_manager:
                            await self.ws_manager.broadcast_isolation_state(alert.agent_id, "ISOLATION_FAILED", output)
                        await self.audit_logger.log(
                            actor_type="agent",
                            actor_id=alert.agent_id,
                            action=AuditAction.NETWORK_ISOLATION_FAILED,
                            target_type="agent",
                            target_id=alert.agent_id,
                            details={"response_id": str(alert_resp.id), "command_id": str(command_id), "error": alert_resp.error_message},
                            db_session=self.db
                        )
                    elif alert_resp.action in (AlertResponseAction.NETWORK_UNISOLATE.value, "ENABLE_NETWORK", "UNISOLATE_HOST"):
                        if self.ws_manager:
                            await self.ws_manager.broadcast_isolation_state(alert.agent_id, "UNISOLATION_FAILED", output)
                        await self.audit_logger.log(
                            actor_type="agent",
                            actor_id=alert.agent_id,
                            action=AuditAction.NETWORK_UNISOLATION_FAILED,
                            target_type="agent",
                            target_id=alert.agent_id,
                            details={"response_id": str(alert_resp.id), "command_id": str(command_id), "error": alert_resp.error_message},
                            db_session=self.db
                        )

                    await self.audit_logger.log(
                        actor_type="agent",
                        actor_id=alert.agent_id,
                        action=AuditAction.RESPONSE_FAILED,
                        target_type="alert",
                        target_id=alert.id,
                        details={"response_id": str(alert_resp.id), "error": alert_resp.error_message},
                        db_session=self.db
                    )

                if self.ws_manager:
                    try:
                        await self.ws_manager.broadcast_alert_to_dashboards({
                            "type": "RESPONSE_STATUS_UPDATED",
                            "alert_id": str(alert.id),
                            "response_id": str(alert_resp.id),
                            "action": alert_resp.action,
                            "status": alert_resp.status.value,
                            "alert_status": alert.status.value,
                            "result": output
                        })
                    except Exception as exc:
                        logger.error(f"Failed broadcasting response completion update: {exc}")

        await self.db.commit()

    async def list_alert_responses(self, alert_id: uuid.UUID) -> List[AlertResponse]:
        res = await self.db.execute(
            select(AlertResponse)
            .where(AlertResponse.alert_id == alert_id)
            .order_by(desc(AlertResponse.requested_at))
        )
        return list(res.scalars().all())

    def _build_command_params(self, action: str, alert: Alert, override_params: Dict[str, Any]) -> Dict[str, Any]:
        """Constructs target parameters from alert metadata and user overrides."""
        params = dict(override_params)

        if action == AlertResponseAction.PROCESS_TERMINATE.value:
            if "pid" not in params and alert.process_id:
                params["pid"] = alert.process_id
            if "process_name" not in params and alert.process_name:
                params["process_name"] = alert.process_name
            if not params.get("pid") and not params.get("process_name"):
                raise ValueError("Process Termination requires target 'pid' or 'process_name'")

        elif action == AlertResponseAction.FILE_QUARANTINE.value:
            if "file_path" not in params and alert.file_path:
                params["file_path"] = alert.file_path
            if not params.get("file_path"):
                raise ValueError("File Quarantine requires target 'file_path'")

        elif action == AlertResponseAction.USER_LOGOUT.value:
            if "username" not in params and alert.username:
                params["username"] = alert.username

        return params
