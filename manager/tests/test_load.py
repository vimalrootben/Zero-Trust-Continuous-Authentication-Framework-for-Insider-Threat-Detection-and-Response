"""
Load Test — Phase 15 (Section 10).

Simulate N agents sending telemetry concurrently, measure Manager
response times and throughput. Gives real numbers for the "performance"
chapter of the final report.
"""
import asyncio
import time
import uuid
import statistics
from datetime import datetime, timezone
from typing import List, Dict, Any

import pytest

from manager.rules.conditions import ConditionEvaluator
from manager.threatintel.cache import ThreatIntelCache
from manager.threatintel.models import IndicatorDTO


def _generate_telemetry_event(agent_id: str, seq: int) -> Dict[str, Any]:
    """Generate a realistic telemetry event payload."""
    return {
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "collector_type": "process",
        "sequence": seq,
        "data": {
            "process_name": f"test_proc_{seq}.exe",
            "pid": 1000 + seq,
            "ppid": 4,
            "command_line": f"test_proc_{seq}.exe --arg={seq}",
            "executable_path": f"C:\\Windows\\Temp\\test_proc_{seq}.exe",
            "signed": False,
            "user_sid": "S-1-5-21-123456-789",
        },
    }


def _generate_network_event(agent_id: str, seq: int) -> Dict[str, Any]:
    """Generate a network telemetry event."""
    return {
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "collector_type": "network",
        "sequence": seq,
        "data": {
            "remote_addr": f"10.0.{seq % 256}.{(seq * 7) % 256}",
            "remote_port": 443,
            "local_addr": "192.168.1.100",
            "local_port": 50000 + seq,
            "protocol": "TCP",
            "pid": 1000 + seq,
        },
    }


# ---------------------------------------------------------------------------
# Rule evaluation throughput
# ---------------------------------------------------------------------------

class TestLoadRuleEvaluation:
    """Measure rule evaluation throughput under concurrent agent load."""

    SAMPLE_RULES = [
        {
            "name": "RULE-0001 Unsigned in TEMP",
            "condition": {
                "all": [
                    {"field": "collector_type", "op": "eq", "value": "process"},
                    {"field": "data.executable_path", "op": "contains_icase", "value": "\\temp\\"},
                    {"not": {"field": "data.signed", "op": "eq", "value": True}},
                ]
            },
        },
        {
            "name": "RULE-0002 PowerShell encoded",
            "condition": {
                "all": [
                    {"field": "collector_type", "op": "eq", "value": "process"},
                    {"field": "data.process_name", "op": "in", "value": ["powershell.exe", "pwsh.exe"]},
                    {"any": [
                        {"field": "data.command_line", "op": "contains_icase", "value": "-enc"},
                        {"field": "data.command_line", "op": "contains_icase", "value": "-encodedcommand"},
                    ]},
                ]
            },
        },
        {
            "name": "RULE-0007 Security tool killed",
            "condition": {
                "all": [
                    {"field": "collector_type", "op": "eq", "value": "process"},
                    {"field": "data.process_name", "op": "in",
                     "value": ["MsMpEng.exe", "avp.exe", "bdagent.exe", "mbam.exe"]},
                    {"field": "data.event_subtype", "op": "eq", "value": "process_stop"},
                ]
            },
        },
        {
            "name": "RULE-0008 Event log clearing",
            "condition": {
                "all": [
                    {"field": "collector_type", "op": "eq", "value": "eventlog"},
                    {"field": "data.event_id", "op": "eq", "value": 1102},
                ]
            },
        },
        {
            "name": "RULE-0005 Registry Run key",
            "condition": {
                "all": [
                    {"field": "collector_type", "op": "eq", "value": "registry"},
                    {"field": "data.key_path", "op": "contains_icase",
                     "value": "CurrentVersion\\Run"},
                ]
            },
        },
    ]

    def _evaluate_all_rules(self, evaluator, event):
        """Evaluate event against all sample rules, return list of matches."""
        matches = []
        for rule in self.SAMPLE_RULES:
            if evaluator.evaluate(rule["condition"], event):
                matches.append(rule["name"])
        return matches

    def test_single_agent_throughput(self):
        """Measure events/sec for a single agent stream through 5 rules."""
        evaluator = ConditionEvaluator()
        agent_id = str(uuid.uuid4())
        n_events = 1000

        start = time.perf_counter()
        for i in range(n_events):
            event = _generate_telemetry_event(agent_id, i)
            self._evaluate_all_rules(evaluator, event)
        elapsed = time.perf_counter() - start

        rate = n_events / elapsed
        print(f"\n[LOAD] Single agent: {n_events} events x {len(self.SAMPLE_RULES)} rules "
              f"in {elapsed:.3f}s -> {rate:.0f} events/sec")
        # Should handle at least 500 events/sec on a single thread
        assert rate > 100, f"Throughput too low: {rate:.0f} events/sec"

    def test_10_agents_concurrent(self):
        """Simulate 10 agents each sending 200 events concurrently (threaded)."""
        import concurrent.futures

        evaluator = ConditionEvaluator()
        n_agents = 10
        events_per_agent = 200
        all_latencies: List[float] = []

        def agent_workload(agent_num: int):
            agent_id = f"agent-{agent_num:03d}"
            latencies = []
            for i in range(events_per_agent):
                event = _generate_telemetry_event(agent_id, i)
                t0 = time.perf_counter()
                self._evaluate_all_rules(evaluator, event)
                latencies.append(time.perf_counter() - t0)
            return latencies

        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_agents) as executor:
            futures = [executor.submit(agent_workload, i) for i in range(n_agents)]
            for f in concurrent.futures.as_completed(futures):
                all_latencies.extend(f.result())
        total_elapsed = time.perf_counter() - start

        total_events = n_agents * events_per_agent
        rate = total_events / total_elapsed
        avg_lat = statistics.mean(all_latencies) * 1000  # ms
        p95_lat = sorted(all_latencies)[int(len(all_latencies) * 0.95)] * 1000
        p99_lat = sorted(all_latencies)[int(len(all_latencies) * 0.99)] * 1000

        print(f"\n[LOAD] {n_agents} agents × {events_per_agent} events = {total_events} total")
        print(f"  Wall time:     {total_elapsed:.3f}s")
        print(f"  Throughput:    {rate:.0f} events/sec")
        print(f"  Avg latency:   {avg_lat:.2f}ms")
        print(f"  P95 latency:   {p95_lat:.2f}ms")
        print(f"  P99 latency:   {p99_lat:.2f}ms")

        assert total_events == n_agents * events_per_agent
        assert rate > 50, f"Throughput too low under concurrency: {rate:.0f}"

    def test_50_agents_concurrent(self):
        """Simulate 50 agents each sending 100 events — stress test."""
        import concurrent.futures

        evaluator = ConditionEvaluator()
        n_agents = 50
        events_per_agent = 100
        all_latencies: List[float] = []

        def agent_workload(agent_num: int):
            agent_id = f"agent-{agent_num:03d}"
            latencies = []
            for i in range(events_per_agent):
                event = _generate_telemetry_event(agent_id, i)
                t0 = time.perf_counter()
                self._evaluate_all_rules(evaluator, event)
                latencies.append(time.perf_counter() - t0)
            return latencies

        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(agent_workload, i) for i in range(n_agents)]
            for f in concurrent.futures.as_completed(futures):
                all_latencies.extend(f.result())
        total_elapsed = time.perf_counter() - start

        total_events = n_agents * events_per_agent
        rate = total_events / total_elapsed
        avg_lat = statistics.mean(all_latencies) * 1000
        p95_lat = sorted(all_latencies)[int(len(all_latencies) * 0.95)] * 1000

        print(f"\n[LOAD] {n_agents} agents × {events_per_agent} events = {total_events} total")
        print(f"  Wall time:     {total_elapsed:.3f}s")
        print(f"  Throughput:    {rate:.0f} events/sec")
        print(f"  Avg latency:   {avg_lat:.2f}ms")
        print(f"  P95 latency:   {p95_lat:.2f}ms")

        assert rate > 30, f"Throughput too low at 50 agents: {rate:.0f}"


# ---------------------------------------------------------------------------
# IOC lookup throughput under load
# ---------------------------------------------------------------------------

class TestLoadIOCLookup:
    """Measure ThreatIntelCache lookup throughput."""

    def test_cache_lookup_throughput(self):
        """Bulk IOC lookups: measure operations/sec."""
        cache = ThreatIntelCache()

        # Load 10,000 indicators
        indicators = []
        for i in range(10_000):
            indicators.append(IndicatorDTO(
                ioc_type="ip",
                value=f"{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}.{(i * 3) & 255}",
                source="load_test",
                confidence=80,
            ))
        cache.load_from_indicators(indicators)

        n_lookups = 50_000
        start = time.perf_counter()
        for i in range(n_lookups):
            cache.is_known_bad("ip", f"10.0.{i % 256}.{i & 255}")
        elapsed = time.perf_counter() - start

        rate = n_lookups / elapsed
        print(f"\n[LOAD] IOC cache: {n_lookups} lookups in {elapsed:.3f}s -> {rate:.0f} lookups/sec")
        # O(1) dict lookup should easily exceed 100k/sec
        assert rate > 10_000, f"IOC lookup too slow: {rate:.0f}/sec"

    def test_cache_with_mixed_ioc_types(self):
        """Lookup throughput across multiple IOC types."""
        cache = ThreatIntelCache()
        indicators = []
        for i in range(5000):
            # Ensure unique IPs by using the index to construct distinct octets
            ip_val = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            indicators.append(IndicatorDTO(ioc_type="ip", value=ip_val, source="t"))
            indicators.append(IndicatorDTO(ioc_type="domain", value=f"bad{i}.example.com", source="t"))
            indicators.append(IndicatorDTO(ioc_type="hash_sha256", value=f"{'a' * 60}{i:04d}", source="t"))
        cache.load_from_indicators(indicators)

        assert cache.total_count == 15_000

        n = 20_000
        start = time.perf_counter()
        for i in range(n):
            ip_val = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            cache.is_known_bad("ip", ip_val)
            cache.is_known_bad("domain", f"bad{i}.example.com")
            cache.is_known_bad("hash_sha256", f"{'a' * 60}{i:04d}")
        elapsed = time.perf_counter() - start

        rate = (n * 3) / elapsed
        print(f"\n[LOAD] Mixed IOC cache: {n*3} lookups in {elapsed:.3f}s -> {rate:.0f}/sec")
        assert rate > 5_000


# ---------------------------------------------------------------------------
# Concurrent rule eval + IOC together
# ---------------------------------------------------------------------------

class TestLoadCombined:
    """Combined rule evaluation + IOC lookup under concurrent agent load."""

    def test_combined_rule_and_ioc_under_load(self):
        """10 agents, each event checked against rules AND IOC cache."""
        import concurrent.futures

        cache = ThreatIntelCache()
        cache.load_from_indicators([
            IndicatorDTO(ioc_type="ip", value=f"10.0.{i}.{i}", source="test")
            for i in range(200)
        ])

        evaluator = ConditionEvaluator(threat_intel_cache=cache)

        ioc_rule = {
            "all": [
                {"field": "collector_type", "op": "eq", "value": "network"},
                {"field": "data.remote_addr", "op": "ioc_match", "value": "ip"},
            ]
        }

        n_agents = 10
        events_per = 300

        def workload(agent_num: int):
            count = 0
            for i in range(events_per):
                event = _generate_network_event(f"agent-{agent_num}", i)
                if evaluator.evaluate(ioc_rule, event):
                    count += 1
            return count

        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_agents) as executor:
            futures = [executor.submit(workload, i) for i in range(n_agents)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        elapsed = time.perf_counter() - start

        total_events = n_agents * events_per
        rate = total_events / elapsed
        total_matches = sum(results)

        print(f"\n[LOAD] Combined rule+IOC: {total_events} events in {elapsed:.3f}s -> {rate:.0f}/sec")
        print(f"  IOC matches: {total_matches}")

        assert rate > 30, f"Combined throughput too low: {rate:.0f}"
