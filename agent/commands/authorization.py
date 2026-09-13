"""Per-agent command integrity, identity and expiry; secrets never enter evidence."""
import hashlib
import hmac
import json
from datetime import datetime, timezone


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sign(payload, secret):
    if not secret:
        raise ValueError('Agent credential is not configured')
    body = {k: v for k, v in payload.items() if k != 'signature'}
    return {**body, 'signature': hmac.new(secret.encode(), canonical(body), hashlib.sha256).hexdigest()}


def verify(payload, secret, agent_id):
    if not secret or payload.get('agent_id') != agent_id:
        raise ValueError('Agent identity or credential mismatch')
    expected = sign(payload, secret)['signature']
    if not hmac.compare_digest(expected, str(payload.get('signature', ''))):
        raise ValueError('Invalid command authorization signature')
    expires = datetime.fromisoformat(payload['expires_at'])
    if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
        raise ValueError('Authorization expired')
    return payload
