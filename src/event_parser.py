import re


def identify_event(log):
    message = log["message"].lower()
    process = log["process"].lower()

    # Session opened events
    if "session opened" in message:

        if process == "login":
            return "LOGIN_SESSION"

        if process == "cron":
            return "CRON_SESSION"

        if process == "sudo":
            return "SUDO_SESSION"

        if "systemd-user" in message:
            return "SYSTEMD_SESSION"

        return "SESSION_OPENED"

    # Session closed events
    if "session closed" in message:

        if process == "login":
            return "LOGIN_SESSION_CLOSED"

        if process == "cron":
            return "CRON_SESSION_CLOSED"

        if process == "sudo":
            return "SUDO_SESSION_CLOSED"

        if "systemd-user" in message:
            return "SYSTEMD_SESSION_CLOSED"

        return "SESSION_CLOSED"

    # User creation
    if "new user:" in message:
        return "USER_CREATED"

    # Sudo command
    if process == "sudo":
        return "SUDO_ACTIVITY"
    # Successful authentication
    if "accepted password" in message:
        return "SUCCESSFUL_LOGIN"

    # Authentication failure
    if any(pattern in message for pattern in [
        "failed password",
        "authentication failure",
        "authentication failed",
        "login failed",
        "invalid user"
    ]):
        return "AUTH_FAILURE"

    return "UNKNOWN"


def extract_user_creation_details(log):
    message = log["message"]

    pattern = (
        r"new user: name=(\S+), UID=(\d+), GID=(\d+), "
        r"home=(\S+), shell=(\S+?)(?:,|$)"
    )

    match = re.search(pattern, message)

    if not match:
        return None

    username, uid, gid, home, shell = match.groups()

    return {
        "username": username,
        "uid": uid,
        "gid": gid,
        "home": home,
        "shell": shell
    }


def extract_sudo_details(log):
    message = log["message"]

    pattern = (
        r"(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*"
        r"USER=(\S+)\s*;\s*COMMAND=(.*)"
    )

    match = re.search(pattern, message)

    if not match:
        return None

    username, tty, pwd, target_user, command = match.groups()

    return {
        "username": username,
        "tty": tty,
        "pwd": pwd,
        "target_user": target_user,
        "command": command
    }


def extract_session_details(log):
    message = log["message"]

    pattern = (
        r"session (opened|closed) for user "
        r"(\S+)\(uid=(\d+)\) by "
        r"(?:(\S+))?\(uid=(\d+)\)"
    )

    match = re.search(pattern, message, re.IGNORECASE)

    if not match:
        return None

    action, username, uid, initiator, initiator_uid = match.groups()

    if initiator is None:
        initiator = "unknown"

    return {
        "action": action.upper(),
        "username": username,
        "uid": uid,
        "initiator": initiator,
        "initiator_uid": initiator_uid
    }


def extract_auth_failure_details(log):
    message = log["message"]

    username = "unknown"
    ip_address = "unknown"

    # Invalid user format
    user_match = re.search(
        r"invalid user\s+(\S+)",
        message,
        re.IGNORECASE
    )

    if user_match:
        username = user_match.group(1)

    else:
        # Normal failed password format
        user_match = re.search(
            r"failed password for\s+(\S+)",
            message,
            re.IGNORECASE
        )

        if user_match:
            username = user_match.group(1)

    # Find IP address
    ip_match = re.search(
        r"from\s+(\d+\.\d+\.\d+\.\d+)",
        message,
        re.IGNORECASE
    )

    if ip_match:
        ip_address = ip_match.group(1)

    return {
        "username": username,
        "ip_address": ip_address
    }


def extract_generic_fields(log):
    message = log["message"]

    fields = {}

    # Extract IP address
    ip_match = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        message
    )

    if ip_match:
        fields["ip_address"] = ip_match.group()

    # Extract UID
    uid_match = re.search(
        r"\bUID[=:\s]+(\d+)",
        message,
        re.IGNORECASE
    )

    if uid_match:
        fields["uid"] = uid_match.group(1)

    # Extract name
    name_match = re.search(
        r"\bname=(\S+?)(?:,|\s|$)",
        message,
        re.IGNORECASE
    )

    if name_match:
        fields["name"] = name_match.group(1)

    # Extract command
    command_match = re.search(
        r"\bCOMMAND=(.*)",
        message,
        re.IGNORECASE
    )

    if command_match:
        fields["command"] = command_match.group(1)

    return fields
def normalize_event(log):

    event = identify_event(log)

    normalized = {
        "timestamp": log.get("timestamp", "unknown"),
        "hostname": log.get("hostname", "unknown"),
        "process": log.get("process", "unknown"),
        "pid": log.get("pid", "unknown"),
        "event_type": event,
        "username": "unknown",
        "ip_address": "unknown",
        "command": "unknown",
        "uid": "unknown",
        "gid": "unknown",
        "home": "unknown",
        "shell": "unknown"
    }

    if "SESSION" in event:

        details = extract_session_details(log)

        if details:
            normalized["username"] = details["username"]

    elif event == "USER_CREATED":

        details = extract_user_creation_details(log)

        if details:
            normalized["username"] = details["username"]
            normalized["uid"] = details["uid"]
            normalized["gid"] = details["gid"]
            normalized["home"] = details["home"]
            normalized["shell"] = details["shell"]

    elif event == "SUDO_ACTIVITY":

        details = extract_sudo_details(log)

        if details:
            normalized["username"] = details["username"]
            normalized["command"] = details["command"]

    elif event == "AUTH_FAILURE":

        details = extract_auth_failure_details(log)

        normalized["username"] = details["username"]
        normalized["ip_address"] = details["ip_address"]

    elif event == "SUCCESSFUL_LOGIN":

        details = extract_successful_login_details(log)

        normalized["username"] = details["username"]
        normalized["ip_address"] = details["ip_address"]

    return normalized

def extract_successful_login_details(log):

    message = log["message"]

    username = "unknown"
    ip_address = "unknown"

    user_match = re.search(
        r"accepted password for\s+(?:invalid user\s+)?(\S+)",
        message,
        re.IGNORECASE
    )

    if user_match:
        username = user_match.group(1)

    ip_match = re.search(
        r"from\s+(\d+\.\d+\.\d+\.\d+)",
        message,
        re.IGNORECASE
    )

    if ip_match:
        ip_address = ip_match.group(1)

    return {
        "username": username,
        "ip_address": ip_address
    }
