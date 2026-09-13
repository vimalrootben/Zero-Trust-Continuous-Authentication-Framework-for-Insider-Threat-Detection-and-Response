"""Lossless durable transport for the existing canonical event model."""
from dataclasses import asdict
from datetime import datetime
from .models import ZTAEvent, ZTAAgent, ZTAUser, ZTAProcess, ZTAMitre, ZTAWazuhRule


def encode(event):
    data = asdict(event)
    data['timestamp'] = event.timestamp.isoformat()
    return data


def decode(data):
    data = dict(data)
    data['timestamp'] = datetime.fromisoformat(data['timestamp'])
    for key, cls in [('agent', ZTAAgent), ('user', ZTAUser), ('process', ZTAProcess), ('mitre', ZTAMitre), ('wazuh_rule', ZTAWazuhRule)]:
        if data.get(key) is not None:
            data[key] = cls(**data[key])
    return ZTAEvent(**data)


def context(event):
    data = asdict(event)
    raw = event.raw_event
    data['data'] = raw.get('data', {})
    for key in ('collector_type', 'failed_count'):
        if key in raw:
            data[key] = raw[key]
    return data
