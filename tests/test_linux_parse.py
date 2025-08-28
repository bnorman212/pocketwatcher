from pocketwatcher.linux import parse_auth_log

SAMPLE = "Jul 25 22:34:12 host sshd[1598]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2"

def test_parse_auth_log():
    evs = list(parse_auth_log(SAMPLE, year=2025))
    assert len(evs) == 1
    assert evs[0].ip == "203.0.113.5"
    assert evs[0].username == "admin"
