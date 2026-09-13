"""Authenticated fixture requests and waits for durable background completion."""
import json
import time
import urllib.request


def headers(path, role='ADMIN'):
    token = 'fixture-agent-token' if ('/agents/heartbeat' in path or '/telemetry/' in path or '/sync/' in path or '/commands/result' in path) else 'fixture-admin-token' if role=='ADMIN' else ''
    return {'Content-Type':'application/json','Authorization':'Bearer '+token}


def wait_processed(base):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        with urllib.request.urlopen(base+'/api/zta/events') as response:
            events=json.loads(response.read())['events']
        if all(e['processing_state']!='PENDING' for e in events):
            assert all(e['processing_state']!='FAILED' for e in events),events
            return
        time.sleep(.02)
    raise AssertionError('Background processing did not finish')
