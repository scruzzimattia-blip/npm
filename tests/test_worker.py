import pytest
from worker import LogHandler, GeoResolver
import json
import os

class MockGeo:
    def resolve(self, ip):
        return {"country_code": "DE", "country_name": "Germany", "city": "Berlin", "asn": "AS1234"}

def test_attack_detection():
    geo = MockGeo()
    handler = LogHandler(geo)
    
    # Test safe paths
    assert not handler.is_attack("/")
    assert not handler.is_attack("/index.html")
    assert not handler.is_attack("/api/v1/data")
    
    # Test attack paths (based on ATTACK_PATTERNS in worker.py)
    assert handler.is_attack("/etc/passwd")
    assert handler.is_attack("/wp-login.php")
    assert handler.is_attack("/.env")
    assert handler.is_attack("/cgi-bin/test.cgi")
    assert handler.is_attack("/?sql=SELECT%20*%20FROM%20users")
    assert handler.is_attack("/.git/config")

def test_ip_cleaning():
    geo = MockGeo()
    handler = LogHandler(geo)
    
    assert handler.clean_ip("192.168.1.1:12345") == "192.168.1.1"
    assert handler.clean_ip("[2001:db8::1]:80") == "2001:db8::1"
    assert handler.clean_ip("1.1.1.1") == "1.1.1.1"

def test_is_bot_detection(mocker):
    # This might require actual log processing logic if we want to test ua.is_bot
    pass
