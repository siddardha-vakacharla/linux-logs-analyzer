from log_parser import parse_log_file
from event_parser import normalize_event


logs = parse_log_file("/var/log/auth.log")


for log in logs:

    event = normalize_event(log)

    if event["event_type"] != "UNKNOWN":

        print("-" * 60)

        for key, value in event.items():

            print(key, ":", value)
