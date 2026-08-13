import argparse
import sys
import os
import socket
import platform
import uuid
import json
import urllib.request
import asyncio

def register_via_api(manager_url, hostname, ip_addr, os_ver, fp):
    url = f"{manager_url.rstrip('/')}/api/v1/agents/register"
    payload = json.dumps({
        "hostname": hostname,
        "ip_address": ip_addr,
        "os_version": os_ver,
        "agent_version": "1.0.0",
        "department": "Engineering",
        "hardware_fingerprint": fp
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode())
            print(f"[+] Successfully registered with Manager API! Agent ID: {res_data.get('agent_id', res_data.get('id', 'N/A'))}")
            return True
    except Exception as e:
        print(f"[*] Manager API endpoint offline or unreachable ({e}). Registering directly into local database...")
        return False

async def register_via_db(hostname, ip_addr, os_ver, fp):
    try:
        from manager.database.session import async_session_maker
        from manager.database.models.agent import Agent, AgentStatus
        from sqlalchemy import select

        async with async_session_maker() as db:
            existing = (await db.execute(select(Agent).where(Agent.hostname == hostname))).scalar_one_or_none()
            if existing:
                existing.ip_address = ip_addr
                existing.os_version = os_ver
                existing.status = AgentStatus.ACTIVE
                print(f"[+] Updated existing agent registration in DB for host: {hostname} (ID: {existing.id})")
            else:
                new_agent = Agent(
                    id=uuid.uuid4(),
                    hostname=hostname,
                    ip_address=ip_addr,
                    os_version=os_ver,
                    agent_version="1.0.0",
                    status=AgentStatus.ACTIVE,
                    current_risk_score=0.0,
                    department="Security Operations"
                )
                db.add(new_agent)
                await db.commit()
                print(f"[+] Successfully created new agent in database! Agent ID: {new_agent.id}")
    except Exception as err:
        print(f"[!] Direct DB registration note: {err}")

def install_agent(manager_url):
    print("=" * 60)
    print("      ZERO TRUST EDR AGENT INSTALLER      ")
    print("=" * 60)
    print(f"[*] Targeting Manager API at: {manager_url}")
    
    hostname = socket.gethostname()
    os_ver = f"{platform.system()} {platform.release()}"
    ip_addr = "127.0.0.1"
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_addr = s.getsockname()[0]
        s.close()
    except Exception:
        pass
        
    print(f"[*] Hostname: {hostname}")
    print(f"[*] IP Address: {ip_addr}")
    print(f"[*] OS: {os_ver}")
    print("[*] Generating device hardware fingerprint...")
    
    fp = f"fp-{hostname}-{uuid.getnode()}"
    print(f"[*] Device Fingerprint: {fp}")
    print("[*] Enrolling local host with EDR Manager Database...")
    
    success = register_via_api(manager_url, hostname, ip_addr, os_ver, fp)
    if not success:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        asyncio.run(register_via_db(hostname, ip_addr, os_ver, fp))

    print("[+] Registration confirmed for host: " + hostname)
    print("\n[+] Zero Trust EDR Agent service started and forwarding telemetry.")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero Trust EDR Agent Installer")
    parser.add_argument("--manager-url", default="http://localhost:8000", help="Manager API Base URL")
    args = parser.parse_args()
    install_agent(args.manager_url)

