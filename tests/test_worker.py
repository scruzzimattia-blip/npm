import pytest
import json
import os
import time
from datetime import datetime
import worker

class MockGeo:
    def resolve(self, ip):
        return {"country_code": "DE", "country_name": "Germany", "city": "Berlin", "asn": "AS1234"}

class MockCrowdSec:
    def __init__(self): self.blocked = []
    def block_ip(self, ip, duration="24h", reason=None):
        self.blocked.append((ip, reason))
        return True

@pytest.fixture
def mock_geo(): return MockGeo()
@pytest.fixture
def mock_crowdsec(): return MockCrowdSec()

def test_calculate_threat_score():
    from worker import calculate_threat_score, THREAT_SCORE_ATTACK_BASE, THREAT_SCORE_SQL_INJECTION, MAX_THREAT_SCORE
    
    score = calculate_threat_score("1.1.1.1", "/index.html", False, 200, False)
    assert score == 0
    
    score = calculate_threat_score("1.1.1.1", "/index.html", True, 200, False)
    assert score == THREAT_SCORE_ATTACK_BASE
    
    score = calculate_threat_score("1.1.1.1", "/index.html?sql=union select", True, 404, False)
    assert score == THREAT_SCORE_ATTACK_BASE + THREAT_SCORE_SQL_INJECTION + 5
    
    score = calculate_threat_score("1.1.1.1", "/.env", True, 404, False)
    assert score == THREAT_SCORE_ATTACK_BASE + 15 + 5
    
    score = calculate_threat_score("1.1.1.1", "/wp-login", False, 401, True)
    assert score == 40
    
    score = calculate_threat_score("1.1.1.1", "/api", False, 500, False)
    assert score == 10
    
    score = calculate_threat_score("1.1.1.1", "/nonexistent", False, 404, False)
    assert score == 5

def test_country_blocking():
    from worker import is_country_blocked, _blocked_countries_cache, _blocked_countries_lock
    
    with _blocked_countries_lock:
        _blocked_countries_cache.clear()
        _blocked_countries_cache.add("CN")
        _blocked_countries_cache.add("RU")
    
    assert is_country_blocked("CN") is True
    assert is_country_blocked("RU") is True
    assert is_country_blocked("US") is False
    assert is_country_blocked(None) is False

def test_login_detection():
    from worker import LOGIN_PATTERNS_COMPILED
    
    test_paths = [
        ("/wp-login.php", True),
        ("/admin", True),
        ("/login", True),
        ("/signin", True),
        ("/auth", True),
        ("/dashboard", True),
        ("/administrator", True),
        ("/phpmyadmin", True),
        ("/console", True),
        ("/", False),
        ("/api/v1/data", False),
        ("/index.html", False),
    ]
    
    for path, expected in test_paths:
        result = any(p.search(path) for p in LOGIN_PATTERNS_COMPILED)
        assert result == expected, f"Failed for path: {path}"

def test_attack_debouncing():
    from worker import should_debounce_attack, _attack_debounce_cache, _attack_debounce_lock
    
    with _attack_debounce_lock:
        _attack_debounce_cache.clear()
    
    ip = "8.8.8.8"
    should_debounce_attack(ip)
    
    with _attack_debounce_lock:
        assert ip in _attack_debounce_cache
    
    with _attack_debounce_lock:
        _attack_debounce_cache.clear()
    
    result = should_debounce_attack(ip)
    assert result is False
    
    time.sleep(0.1)
    result = should_debounce_attack(ip)
    assert result is True

def test_rate_limit_db_fallback(mock_geo):
    from worker import LogHandler
    import worker
    
    worker.IGNORED_IPS_SET = set()
    worker.IGNORED_NETWORKS = []
    
    handler = LogHandler(mock_geo)
    
    result = handler.get_rate_limit_db("192.168.1.100")
    assert result == (0, False)

def test_worker_ip_utilities():
    from worker import should_ignore_ip, ATTACK_PATTERNS_COMPILED, LOGIN_PATTERNS_COMPILED
    import ipaddress
    import worker
    
    assert should_ignore_ip("127.0.0.1") is True
    assert should_ignore_ip("192.168.1.1") is True
    assert should_ignore_ip("10.0.0.1") is True
    assert should_ignore_ip("172.16.0.1") is True
    assert should_ignore_ip("8.8.8.8") is False
    assert should_ignore_ip("1.1.1.1") is False
    
    worker.IGNORED_NETWORKS = [ipaddress.ip_network("1.2.3.4", strict=False)]
    assert should_ignore_ip("1.2.3.4") is True
    worker.IGNORED_NETWORKS = []

    is_attack = lambda p: any(r.search(p) for r in ATTACK_PATTERNS_COMPILED)
    assert not is_attack("/")
    assert not is_attack("/index.html")
    assert not is_attack("/api/v1/data")
    assert is_attack("/etc/passwd")
    assert is_attack("/wp-login.php")
    assert is_attack("/.env")
    assert is_attack("/cgi-bin/test.cgi")
    assert is_attack("/.git/config")
    assert is_attack("/ETC/PASSWD")
    
    is_login = lambda p: any(r.search(p) for r in LOGIN_PATTERNS_COMPILED)
    assert is_login("/wp-login")
    assert is_login("/admin")
    assert is_login("/login")
    assert not is_login("/")

def test_log_handler_ip_cleaning(mock_geo):
    handler = worker.LogHandler(mock_geo)
    
    assert handler.clean_ip("192.168.1.1:12345") == "192.168.1.1"
    assert handler.clean_ip("[2001:db8::1]:80") == "2001:db8::1"
    assert handler.clean_ip("1.1.1.1") == "1.1.1.1"
    assert handler.clean_ip("") == ""
    assert handler.clean_ip("") == ""

def test_log_processing(session, mock_geo, mock_crowdsec, tmp_path):
    safe_log = tmp_path / "access.log"
    safe_log.write_text(json.dumps({
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "8.8.8.8:443",
        "RequestUserAgent": "Mozilla/5.0",
        "RequestPath": "/safe-path",
        "RequestHost": "example.com",
        "RequestMethod": "GET",
        "RequestProtocol": "HTTP/2.0",
        "DownstreamStatus": 200,
        "Duration": 500000,
        "DownstreamContentSize": 1024
    }) + "\n")
    
    attack_log = tmp_path / "attack.log"
    attack_log.write_text(json.dumps({
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "9.9.9.9:443",
        "RequestUserAgent": "EvilBot/1.0",
        "RequestPath": "/.env",
        "RequestHost": "example.com",
        "RequestMethod": "GET",
        "DownstreamStatus": 404
    }) + "\n")
    
    ignored_log = tmp_path / "ignored.log"
    ignored_log.write_text(json.dumps({
        "StartLocal": datetime.now().isoformat(),
        "ClientAddr": "127.0.0.1:443",
        "RequestPath": "/",
        "RequestHost": "localhost"
    }) + "\n")
    
    original_file = worker.LOG_FILE
    
    # Test 1: Safe log
    worker.LOG_FILE = str(safe_log)
    worker.SessionLocal = lambda: session
    handler = worker.LogHandler(mock_geo, mock_crowdsec)
    handler.process_new_lines()
    
    entry = session.query(worker.AccessLog).filter_by(client_addr="8.8.8.8").first()
    assert entry is not None
    assert entry.request_path == "/safe-path"
    assert entry.is_attack is False
    assert entry.country_code == "DE"
    session.commit()
    
    # Test 2: Attack log (new handler to avoid file state issues)
    worker.LOG_FILE = str(attack_log)
    handler2 = worker.LogHandler(mock_geo, mock_crowdsec)
    handler2.process_new_lines()
    
    entry = session.query(worker.AccessLog).filter_by(client_addr="9.9.9.9").first()
    assert entry is not None
    assert entry.is_attack is True
    assert len(mock_crowdsec.blocked) == 1
    assert mock_crowdsec.blocked[0][0] == "9.9.9.9"
    session.commit()
    
    # Test 3: Ignored IP (new handler)
    worker.LOG_FILE = str(ignored_log)
    handler3 = worker.LogHandler(mock_geo, mock_crowdsec)
    handler3.process_new_lines()
    
    entry = session.query(worker.AccessLog).filter_by(client_addr="127.0.0.1").first()
    assert entry is None

    worker.LOG_FILE = original_file


def test_parse_nginx_combined_line():
    from worker import parse_nginx_combined_line

    line = (
        '172.17.0.1 - - [10/Apr/2026:12:00:00 +0000] '
        '"GET /api/foo?x=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    )
    p = parse_nginx_combined_line(line)
    assert p is not None
    assert p.ClientAddr == "172.17.0.1"
    assert p.RequestPath == "/api/foo?x=1"
    assert p.RequestMethod == "GET"
    assert p.DownstreamStatus == 200
    assert p.DownstreamContentSize == 1234
    assert p.EntryPointName == "nginx"


def test_nginx_log_processing(session, mock_geo, mock_crowdsec, tmp_path):
    import worker

    nginx_log = tmp_path / "nginx_access.log"
    nginx_log.write_text(
        '8.8.8.8 - - [10/Apr/2026:12:00:00 +0000] '
        '"GET /safe-path HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
    )

    original_file = worker.LOG_FILE
    original_fmt = worker.ACCESS_LOG_FORMAT

    worker.LOG_FILE = str(nginx_log)
    worker.ACCESS_LOG_FORMAT = "nginx"
    worker.SessionLocal = lambda: session

    handler = worker.LogHandler(mock_geo, mock_crowdsec)
    handler.process_new_lines()

    entry = session.query(worker.AccessLog).filter_by(client_addr="8.8.8.8").first()
    assert entry is not None
    assert entry.request_path == "/safe-path"
    assert entry.is_attack is False

    worker.LOG_FILE = original_file
    worker.ACCESS_LOG_FORMAT = original_fmt