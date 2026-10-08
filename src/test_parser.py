from log_parser import parse_log_file
from event_parser import (
    identify_event,
    extract_session_details,
    extract_user_creation_details,
    extract_sudo_details,
    extract_auth_failure_details,
    extract_generic_fields
)


logs = parse_log_file("/var/log/auth.log")


for number, log in enumerate(logs, 1):

    event = identify_event(log)

    if event == "UNKNOWN":
        continue

    print("Log Entry :", number)
    print("Timestamp :", log["timestamp"])
    print("Hostname  :", log["hostname"])
    print("Process   :", log["process"])

    if log["pid"]:
        print("PID       :", log["pid"])

    print("Event     :", event)

    # Session events
    if "SESSION" in event:

        details = extract_session_details(log)

        if details:
            print("Username      :", details["username"])
            print("UID           :", details["uid"])
            print("Initiated By  :", details["initiator"])
            print("Initiator UID :", details["initiator_uid"])

    # User creation
    elif event == "USER_CREATED":

        details = extract_user_creation_details(log)

        if details:
            print("Username :", details["username"])
            print("UID      :", details["uid"])
            print("GID      :", details["gid"])
            print("Home     :", details["home"])
            print("Shell    :", details["shell"])

    # Sudo activity
    elif event == "SUDO_ACTIVITY":

        details = extract_sudo_details(log)

        if details:
            print("Username    :", details["username"])
            print("TTY         :", details["tty"])
            print("PWD         :", details["pwd"])
            print("Target User :", details["target_user"])
            print("Command     :", details["command"])

    # Authentication failure
    elif event == "AUTH_FAILURE":

        details = extract_auth_failure_details(log)

        print("Username   :", details["username"])
        print("IP Address :", details["ip_address"])

    # Generic fields
    generic_fields = extract_generic_fields(log)

    for key, value in generic_fields.items():

        # Avoid printing UID twice for session events
        if key == "uid" and "SESSION" in event:
            continue

        # Avoid printing fields that were already displayed
        if "SESSION" in event and key == "uid":
            continue

        print(f"{key} : {value}")

    print("-" * 60)
