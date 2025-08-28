from pocketwatcher.utils import parse_window
from datetime import timedelta

def test_parse_window():
    assert parse_window("5m") == timedelta(minutes=5)
    assert parse_window("30s") == timedelta(seconds=30)
    assert parse_window("1h") == timedelta(hours=1)
