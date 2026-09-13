"""Controlled fixtures; Windows actions are mocked, never claimed as live validation."""
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import requests
from zta.api.server import create_zta_server
from zta.agent.agent_daemon import ZTAAgentDaemon
from zta.agent.commands.authorization import sign, verify
from zta.engine.events.wazuh_adapter import ZTAEventAdapter
from zta.engine.events.serialization import encode
from zta.powershell.ps_executor import PSResult

TOKEN = 'test-agent-credential'


def eventually(predicate):
    deadline = time.monotonic()+8
    while time.monotonic()<deadline:
        value = predicate()
        if value: return value
        time.sleep(.03)
    raise AssertionError('Expected persisted background state was not reached')


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setenv('ZTA_AGENT_TOKENS', json.dumps({'endpoint':TOKEN}))
    monkeypatch.setenv('ZTA_ADMIN_TOKEN','test-admin-credential')
    server = create_zta_server(port=0,db_path=tmp_path/'manager.db')
    thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    agent = ZTAAgentDaemon('http://127.0.0.1:'+str(server.server_port),str(tmp_path/'agent.db'),agent_id='endpoint',token=TOKEN)
    yield server,agent
    server.shutdown();server.server_close()


def raw(identifier='event', matching=True):
    return {'id':identifier,'timestamp':datetime.now(timezone.utc).isoformat(), 'agent':{'id':'endpoint','name':'host'},
            'event_type':'SERVICE_INSTALL' if matching else 'SYSTEM_EVENT', 'user':{'name':'user','session_id':7}}


def submit(server,agent,event):
    response = agent.post('/api/v1/telemetry/bulk',[event])
    assert response.status_code == 201,response.text
    repo = server.runtime[0]
    eventually(lambda: next((e for e in repo.get_recent_events() if e['event_id']==event['id'] and e['processing_state'] in ('COMPLETED','FAILED')),None))
    row = next(e for e in repo.get_recent_events() if e['event_id']==event['id'])
    assert row['processing_state']=='COMPLETED',row['processing_error']
    return response


def test_no_match_and_real_condition_id_cannot_override(runtime):
    server,agent = runtime
    event=raw(matching=False);event['rule']={'id':'RULE-0004','level':12}
    submit(server,agent,event)
    repo=server.runtime[0]
    assert repo.get_incidents()==[]
    with repo.db.get_connection() as conn:
        assert conn.execute('SELECT COUNT(*) FROM rule_evaluations').fetchone()[0]==15
        assert conn.execute('SELECT SUM(result) FROM rule_evaluations').fetchone()[0]==0


def test_background_logout_chain_replay_and_verified_result(runtime):
    server,agent = runtime
    assert agent.send_heartbeat()
    event=raw()
    submit(server,agent,event)
    repo=server.runtime[0]
    commands=repo.get_commands(); assert len(commands)==1
    assert commands[0]['params']=={'UserName':'user','SessionId':'7'}
    before=(len(repo.get_rule_matches()),len(repo.get_incidents()),len(repo.get_audit_logs(1000)),len(repo.get_agent_risk_history('endpoint')))
    submit(server,agent,event)
    assert before==(len(repo.get_rule_matches()),len(repo.get_incidents()),len(repo.get_audit_logs(1000)),len(repo.get_agent_risk_history('endpoint')))
    executor=MagicMock(); executor.execute_template.return_value=PSResult(True,'Session absent',verification='SESSION_NOT_ACTIVE')
    agent.command_receiver.ps_executor=executor
    assert agent.send_heartbeat()
    executor.execute_template.assert_called_once()
    assert repo.get_commands()[0]['status']=='SUCCESS'
    assert repo.get_incidents()[0]['response_status']=='SUCCESS'
    chain=repo.get_incident_by_id(repo.get_incidents()[0]['incident_id'])
    assert len(chain['policy_evaluations'])==5
    assert chain['risk_history'] and chain['audit']
    assert agent.send_heartbeat()
    executor.execute_template.assert_called_once()


def test_alert_only_never_dispatches_and_missing_session_blocks(runtime):
    server,agent=runtime;repo=server.runtime[0]
    with repo.db.get_connection() as conn: conn.execute("UPDATE policies SET mode='ALERT_ONLY' WHERE policy_id='POL-LOGOUT-001'")
    submit(server,agent,raw())
    assert repo.get_commands()==[]
    assert repo.get_incidents()[0]['response_status']=='RECOMMENDED_ONLY'
    with repo.db.get_connection() as conn: conn.execute("UPDATE policies SET mode='ENFORCE' WHERE policy_id='POL-LOGOUT-001'")
    event=raw('missing');event['user'].pop('session_id');submit(server,agent,event)
    assert repo.get_commands()==[]
    assert repo.get_incidents()[0]['response_status']=='BLOCKED'


def test_authentication_expiry_and_wrong_agent(runtime):
    server,agent=runtime
    url=agent.manager_url
    assert requests.post(url+'/api/v1/agents/heartbeat',json={'agent_id':'endpoint'}).status_code==400
    assert requests.post(url+'/api/zta/commands',json={'agent_id':'endpoint','action':'LOGOUT_USER'},headers={'X-User-Role':'ADMIN'}).status_code==403
    executor=MagicMock();agent.command_receiver.ps_executor=executor
    cmd={'command_id':'x','agent_id':'endpoint','action_type':'LOGOUT_USER','params':{'UserName':'user','SessionId':'7'},'status':'DISPATCHED','expires_at':(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()}
    report=agent.command_receiver.process_command(sign(cmd,TOKEN));assert report.status=='FAILED'
    cmd['expires_at']=(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat();cmd['agent_id']='other'
    assert agent.command_receiver.process_command(sign(cmd,TOKEN)).status=='FAILED'
    executor.execute_template.assert_not_called()


def test_offline_queue_and_approved_cache_sync(runtime):
    server,agent=runtime;repo=server.runtime[0]
    # Existing rule explicitly approved in this isolated fixture only.
    with repo.db.get_connection() as conn: conn.execute("UPDATE rules SET allow_offline=1 WHERE rule_id='RULE-0004'")
    assert agent.send_heartbeat()
    executor=MagicMock();executor.execute_template.return_value=PSResult(True,'Session absent',verification='SESSION_NOT_ACTIVE')
    agent.command_receiver.ps_executor=executor
    agent.connection_state='OFFLINE'
    event=raw();agent.collect(event)
    agent.collect(raw('normal',False))
    assert agent.offline_queue.queue_depth()==2
    executor.execute_template.assert_called_once()
    saved=agent.offline_queue.dequeue_batch()
    agent.sync_offline_queue()
    assert agent.offline_queue.queue_depth()==0
    incident=repo.get_incidents()[0]
    assert incident['execution_source']=='AGENT_OFFLINE'
    assert incident['response_status']=='SUCCESS'
    assert repo.get_commands()[0]['synced_at']
    count=len(repo.get_audit_logs(1000))
    for record in saved:agent.offline_queue.enqueue(record['event_id'],record['collector_type'],record['severity'],record['payload'])
    agent.sync_offline_queue()
    assert len(repo.get_commands())==1 and len(repo.get_incidents())==1
    assert len(repo.get_audit_logs(1000))==count


def test_offline_unapproved_rule_never_executes(runtime):
    server,agent=runtime
    assert agent.send_heartbeat()
    executor=MagicMock();agent.command_receiver.ps_executor=executor
    agent.connection_state='OFFLINE';agent.collect(raw())
    executor.execute_template.assert_not_called()
    assert agent.offline_queue.queue_depth()==1


def test_worker_timeout_and_stale_syncing_agent(runtime):
    server,agent=runtime;repo=server.runtime[0]
    assert agent.send_heartbeat();submit(server,agent,raw())
    past=(datetime.now(timezone.utc)-timedelta(minutes=5)).isoformat()
    with repo.db.get_connection() as conn:
        conn.execute("UPDATE agents SET last_seen=?,connection_state='SYNCING'",(past,))
        conn.execute('UPDATE commands SET expires_at=?',(past,))
    server.worker.wake.set()
    eventually(lambda:repo.get_commands()[0]['status']=='EXPIRED')
    assert repo.get_agents()[0]['connection_state']=='OFFLINE'
    assert any(a['event_type']=='AGENT_OFFLINE' for a in repo.get_audit_logs())


def test_pending_event_restart_and_shared_runtime(runtime,tmp_path):
    server,agent=runtime
    other=create_zta_server(port=0,runtime=server.runtime)
    assert other.runtime[1] is server.runtime[1] and other.runtime[2] is server.runtime[2]
    other.server_close()
    repo=server.runtime[0]; server.worker.close()
    repo.save_event(ZTAEventAdapter.from_dict(raw()))
    from zta.api.background import BackgroundWorker
    worker=BackgroundWorker(server.runtime[2]);worker.start()
    try: eventually(lambda:repo.get_incidents())
    finally:worker.close()


def test_result_without_verification_or_wrong_identity_rejected(runtime):
    server,agent=runtime
    submit(server,agent,raw())
    response=agent.post('/api/v1/agents/heartbeat',agent.get_system_telemetry());assert response.status_code==200
    cmd=response.json()['pending_commands'][0]
    report={'command_id':cmd['command_id'],'agent_id':'endpoint','status':'SUCCESS'}
    assert agent.post('/api/v1/commands/result',report).status_code==400
    assert server.runtime[0].get_commands()[0]['status']=='DISPATCHED'


def test_database_migration_preserves_existing_content(tmp_path):
    import sqlite3
    from zta.storage.database import ZTADatabase
    target=tmp_path/'migration.db'
    ZTADatabase(target)
    with sqlite3.connect(target) as conn:
        for table in ('schema_migrations','rule_evaluations','sync_receipts'):
            conn.execute('DROP TABLE '+table)
        for table, column in [('zta_events','normalized_json'),('zta_events','processing_state'),('zta_events','processing_error'),('policy_evaluations','condition_trace_json'),('commands','executing_at'),('commands','synced_at'),('agents','agent_version'),('agents','collector_error')]:
            conn.execute('ALTER TABLE '+table+' DROP COLUMN '+column)
    with sqlite3.connect(target) as conn:
        before={t:conn.execute('SELECT * FROM '+t).fetchall() for t in ('rules','policies','incidents','commands','agents')}
    ZTADatabase(target);ZTADatabase(target)
    with sqlite3.connect(target) as conn:
        for table in ('rules','policies','incidents'):
            assert before[table]==conn.execute('SELECT * FROM '+table).fetchall()
        conn.execute('DELETE FROM rules');conn.execute('DELETE FROM policies')
    ZTADatabase(target)
    with sqlite3.connect(target) as conn:
        assert conn.execute('SELECT COUNT(*) FROM rules').fetchone()[0]==0
        assert conn.execute('SELECT COUNT(*) FROM policies').fetchone()[0]==0


def test_atomic_pipeline_failure_rolls_back_then_retries(runtime,monkeypatch):
    server,agent=runtime;repo=server.runtime[0]
    original=repo.save_incident
    def fail(*args,**kwargs): raise RuntimeError('Injected persistence failure')
    monkeypatch.setattr(repo,'save_incident',fail)
    response=agent.post('/api/v1/telemetry/bulk',[raw()]);assert response.status_code==201
    eventually(lambda:repo.get_recent_events()[0]['processing_state']=='FAILED')
    assert repo.get_rule_matches()==[] and repo.get_agent_risk_history('endpoint')==[]
    monkeypatch.setattr(repo,'save_incident',original)
    response=requests.post(agent.manager_url+'/api/zta/events/event/retry',json={},headers={'Authorization':'Bearer test-admin-credential'})
    assert response.status_code==200,response.text
    eventually(lambda:repo.get_incidents())
    assert len(repo.get_rule_matches())==1


def test_websocket_shared_across_agent_and_dashboard_ports(runtime):
    import socket,base64,struct
    server,agent=runtime
    dashboard=create_zta_server(port=0,runtime=server.runtime)
    thread=threading.Thread(target=dashboard.serve_forever,daemon=True);thread.start()
    sock=socket.create_connection(('127.0.0.1',dashboard.server_port),timeout=3)
    try:
        sock.sendall((f'GET /api/zta/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {base64.b64encode(b"0123456789abcdef").decode()}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        data=b''
        while b'\r\n\r\n' not in data: data+=sock.recv(1)
        assert b'101 Switching Protocols' in data
        eventually(lambda:bool(server.runtime[1]._ws_clients))
        assert agent.send_heartbeat()
        def exact(n):
            result=b''
            while len(result)<n:result+=sock.recv(n-len(result))
            return result
        head=exact(2);size=head[1]&127
        if size==126:size=struct.unpack('!H',exact(2))[0]
        elif size==127:size=struct.unpack('!Q',exact(8))[0]
        message=json.loads(exact(size))
        assert message['event']=='agent.reconnecting'
        assert message['data']['agent_id']=='endpoint'
    finally:
        sock.close();dashboard.shutdown();dashboard.server_close()


def test_real_jsonl_collection_keeps_partial_lines_and_checkpoint(tmp_path):
    from zta.agent.collectors import JsonlCollector
    path=tmp_path/'feed.jsonl'
    event=raw();event['id']='feed-event'
    path.write_text(json.dumps(event))
    agent=ZTAAgentDaemon(db_path=str(tmp_path/'agent.db'),agent_id='endpoint',telemetry_path=str(path))
    agent.collector.poll(agent.collect)
    assert agent.offline_queue.queue_depth()==0
    with path.open('a') as stream:stream.write('\n')
    agent.collector.poll(agent.collect);agent.collector.poll(agent.collect)
    assert agent.offline_queue.queue_depth()==1
    assert agent.state.get('jsonl:'+str(path.resolve()))['offset']==path.stat().st_size


def test_command_journal_replay_does_not_execute_twice(runtime):
    server,agent=runtime
    command=sign({'command_id':'journal-test','agent_id':'endpoint','action_type':'LOGOUT_USER',
                  'params':{'UserName':'user','SessionId':'7'},'status':'DISPATCHED',
                  'expires_at':(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat()},TOKEN)
    executor=MagicMock();executor.execute_template.return_value=PSResult(False,'','Controlled failure')
    agent.command_receiver.ps_executor=executor
    first=agent.execute_command(command);second=agent.execute_command(command)
    assert first==second
    executor.execute_template.assert_called_once()


def test_stale_event_cannot_trigger_live_logout(runtime):
    server,agent=runtime;event=raw()
    event['timestamp']=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
    submit(server,agent,event)
    assert server.runtime[0].get_commands()==[]
    assert server.runtime[0].get_incidents()[0]['response_status']=='BLOCKED'


def test_signed_command_cannot_be_retargeted(runtime):
    server,agent=runtime
    command=sign({'command_id':'tamper-test','agent_id':'endpoint','action_type':'LOGOUT_USER',
                  'params':{'UserName':'user','SessionId':'7'},'status':'DISPATCHED',
                  'expires_at':(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat()},TOKEN)
    command['params']['SessionId']='8'
    with pytest.raises(ValueError,match='signature'):agent.execute_command(command)
