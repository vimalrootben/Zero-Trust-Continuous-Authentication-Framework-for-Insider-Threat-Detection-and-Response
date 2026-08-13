import enum

class AuditAction(str, enum.Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    ACCOUNT_LOCKED = "account_locked"
    AGENT_REGISTERED = "agent_registered"
    AGENT_DECOMMISSIONED = "agent_decommissioned"
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_DELETED = "policy_deleted"
    COMMAND_ISSUED = "command_issued"
    ALERT_CREATED = "alert_created"
    ALERT_STATUS_UPDATED = "alert_status_updated"
    ALERT_ASSIGNED = "alert_assigned"
    SELF_PROTECTION_EVENT = "self_protection_event"
