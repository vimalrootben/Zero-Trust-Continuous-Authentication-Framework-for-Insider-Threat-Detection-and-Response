"""
Unit tests for USBCollector (A10).
"""
import time
from agent.collectors.usb_collector import USBCollector, WMIUSBSubscriber
from agent.storage.models import TelemetryEventDTO


class MockWMIUSBSubscriber(WMIUSBSubscriber):
    """Mock subscriber emitting USB insertion events."""

    def __init__(self, sample_events=None):
        self.sample_events = sample_events or []

    def subscribe(self, on_event, stop_event):
        for ev in self.sample_events:
            if stop_event.is_set():
                break
            on_event(ev)
        stop_event.wait(timeout=0.1)


def test_usb_collector_events():
    events = []
    subscriber = MockWMIUSBSubscriber([
        {
            "device_id": "\\\\.\\PHYSICALDRIVE1",
            "device_description": "Kingston DataTraveler 3.0 USB Device",
            "serial_number": "001122334455",
            "vendor_id": "0951",
            "product_id": "1666",
            "drive_letter": "E:",
            "event_type": "connected",
            "file_copy_activity": None,
        }
    ])

    collector = USBCollector(
        event_sink=events.append,
        subscriber=subscriber,
    )
    assert collector.collector_type() == "usb"

    collector.start()
    time.sleep(0.2)
    collector.stop()

    assert len(events) == 1
    ev = events[0]
    assert ev.collector_type == "usb"
    assert ev.event_type == "usb_connected"
    assert ev.data["vendor_id"] == "0951"
