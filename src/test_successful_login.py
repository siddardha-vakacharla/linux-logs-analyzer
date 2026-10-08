from event_parser import normalize_event


log = {
    "timestamp": "2026-09-05T10:01:00+00:00",
    "hostname": "server1",
    "process": "sshd",
    "pid": "1006",
    "message": "Accepted password for siddu from 192.168.1.50 port 5010 ssh2"
}


event = normalize_event(log)


for key, value in event.items():
    print(key, ":", value)
