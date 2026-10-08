import sys
from datetime import datetime

from log_parser import parse_log_file

from event_parser import (
    identify_event,
    normalize_event
)


def analyze_logs(log_file):

    logs = parse_log_file(log_file)

    event_counts = {}
    normalized_events = []
    auth_failures = []

    for log in logs:

        event = identify_event(log)

        # Count events
        if event in event_counts:
            event_counts[event] += 1
        else:
            event_counts[event] = 1

        # Create standard event
        normalized = normalize_event(log)

        normalized_events.append(normalized)

        # Collect authentication failures
        if event == "AUTH_FAILURE":

            auth_failures.append({
                "timestamp": normalized["timestamp"],
                "process": normalized["process"],
                "username": normalized["username"],
                "ip_address": normalized["ip_address"]
            })

    return (
        len(logs),
        event_counts,
        auth_failures,
        normalized_events
    )


def get_alert_severity(alert_type):

    severity_map = {
        "BRUTE_FORCE_ATTACK": "HIGH",
        "POSSIBLE_ACCOUNT_COMPROMISE": "HIGH"
    }

    return severity_map.get(
        alert_type,
        "MEDIUM"
    )


def detect_account_compromise(
    normalized_events,
    failure_threshold=3,
    time_window=60
):

    alerts = []

    # Group authentication failures by IP
    failures_by_ip = {}

    for event in normalized_events:

        if event["event_type"] != "AUTH_FAILURE":
            continue

        ip = event["ip_address"]

        if ip == "unknown":
            continue

        if ip not in failures_by_ip:
            failures_by_ip[ip] = []

        failures_by_ip[ip].append(event)

    # Check successful logins
    for event in normalized_events:

        if event["event_type"] != "SUCCESSFUL_LOGIN":
            continue

        login_ip = event["ip_address"]

        if login_ip not in failures_by_ip:
            continue

        login_time = datetime.fromisoformat(
            event["timestamp"]
        )

        recent_failures = []

        for failure in failures_by_ip[login_ip]:

            failure_time = datetime.fromisoformat(
                failure["timestamp"]
            )

            difference = (
                login_time - failure_time
            ).total_seconds()

            if 0 <= difference <= time_window:

                recent_failures.append(
                    failure
                )

        if len(recent_failures) >= failure_threshold:

            alert_risk_score = 60

            alerts.append({
                "alert_type":
                    "POSSIBLE_ACCOUNT_COMPROMISE",

                "risk_score":
                    alert_risk_score,

                "severity":
                    get_alert_severity(
                        "POSSIBLE_ACCOUNT_COMPROMISE"
                    ),

                "username":
                    event["username"],

                "ip_address":
                    login_ip,

                "failed_attempts":
                    len(recent_failures),

                "successful_login":
                    event["timestamp"],

                "reason": (
                    f"{len(recent_failures)} "
                    "failed authentication attempts "
                    "were followed by a successful "
                    "login from the same IP within "
                    f"{time_window} seconds."
                )
            })

    return alerts

def detect_suspicious_sudo(normalized_events):

    alerts = []

    high_risk_patterns = [
        "/etc/shadow",
        "/etc/sudoers",
        "passwd root",
        "usermod",
        "useradd"
    ]

    medium_risk_patterns = [
        "/etc/passwd",
        "chmod",
        "chown",
        "su "
    ]

    for event in normalized_events:

        if event["event_type"] != "SUDO_ACTIVITY":
            continue

        command = event["command"].lower()
        executing_user = event["username"]

        severity = None
        risk_score = 0
        matched_pattern = None

        # High-risk commands
        for pattern in high_risk_patterns:

            if pattern in command:

                severity = "HIGH"
                risk_score = 50
                matched_pattern = pattern
                break

        # Medium-risk commands
        if severity is None:

            for pattern in medium_risk_patterns:

                if pattern in command:

                    severity = "MEDIUM"
                    risk_score = 30
                    matched_pattern = pattern
                    break

        # Ignore normal sudo commands
        if severity is None:
            continue

        # Sudo activity performed by non-root users
        if executing_user != "root":

            if severity == "MEDIUM":
                severity = "HIGH"
                risk_score = 40

            elif severity == "HIGH":
                risk_score = 60

        alerts.append({
            "alert_type":
                "SUSPICIOUS_SUDO_ACTIVITY",

            "timestamp":
                event["timestamp"],

            "username":
                event["username"],

            "command":
                event["command"],

            "matched_pattern":
                matched_pattern,

            "severity":
                severity,

            "risk_score":
                risk_score
        })

    return alerts

def detect_sudo_burst(
    suspicious_sudo_alerts,
    threshold=3,
    time_window=60
):

    alerts = []

    # Group suspicious sudo activity by user
    users = {}

    for alert in suspicious_sudo_alerts:

        username = alert["username"]

        if username not in users:
            users[username] = []

        users[username].append(alert)

    # Check each user's activity
    for username, user_alerts in users.items():

        for i in range(len(user_alerts)):

            start_time = datetime.fromisoformat(
                user_alerts[i]["timestamp"]
            )

            count = 0

            for alert in user_alerts[i:]:

                alert_time = datetime.fromisoformat(
                    alert["timestamp"]
                )

                difference = (
                    alert_time - start_time
                ).total_seconds()

                if 0 <= difference <= time_window:
                    count += 1

                else:
                    break

            if count >= threshold:

                alerts.append({
                    "alert_type":
                        "SUSPICIOUS_SUDO_BURST",

                    "username":
                        username,

                    "start_time":
                        user_alerts[i]["timestamp"],

                    "command_count":
                        count,

                    "time_window":
                        time_window,

                    "severity":
                        "HIGH",

                    "risk_score":
                        50
                })

                break

    return alerts

def detect_suspicious_user_creation(normalized_events):

    alerts = []

    suspicious_names = [
        "hacker",
        "test",
        "temp",
        "guest",
        "admin1"
    ]

    suspicious_shells = [
        "/bin/bash",
        "/bin/sh",
        "/bin/zsh"
    ]

    for event in normalized_events:

        if event["event_type"] != "USER_CREATED":
            continue

        username = event["username"]
        shell = event["shell"]

        matched_pattern = None

        # Check suspicious username
        for pattern in suspicious_names:

            if pattern in username.lower():

                matched_pattern = (
                    f"username: {pattern}"
                )

                break

        # Check interactive shell
        if matched_pattern is None:

            for shell_pattern in suspicious_shells:

                if shell == shell_pattern:

                    matched_pattern = (
                        f"interactive shell: {shell}"
                    )

                    break

        if matched_pattern is None:
            continue

        alerts.append({
            "alert_type":
                "SUSPICIOUS_USER_CREATION",

            "timestamp":
                event["timestamp"],

            "username":
                username,

            "shell":
                shell,

            "severity":
                "MEDIUM",

            "risk_score":
                30,

            "reason":
                matched_pattern
        })

    return alerts

def display_summary(
    total_logs,
    event_counts
):

    print()
    print("=" * 60)
    print("LINUX LOG ANALYSIS SUMMARY")
    print("=" * 60)

    print()
    print(
        "Total Log Entries :",
        total_logs
    )

    print()
    print("IMPORTANT EVENTS")
    print("-" * 60)

    for event, count in event_counts.items():

        if event != "UNKNOWN":

            print(
                f"{event} : {count}"
            )

    print()
    print("OTHER EVENTS")
    print("-" * 60)

    if "UNKNOWN" in event_counts:

        print(
            "UNKNOWN :",
            event_counts["UNKNOWN"]
        )

    print()
    print("=" * 60)


def display_auth_failures(
    auth_failures
):

    print()
    print("=" * 60)
    print("AUTHENTICATION FAILURE ANALYSIS")
    print("=" * 60)

    if not auth_failures:

        print()
        print(
            "No authentication failures found."
        )

        return

    print()

    for number, failure in enumerate(
        auth_failures,
        1
    ):

        print(
            "Failure :",
            number
        )

        print(
            "Timestamp :",
            failure["timestamp"]
        )

        print(
            "Process :",
            failure["process"]
        )

        print(
            "Username :",
            failure["username"]
        )

        print(
            "IP Address :",
            failure["ip_address"]
        )

        print("-" * 60)


def detect_brute_force(
    auth_failures,
    threshold=5,
    time_window=60
):

    failures_by_ip = {}

    for failure in auth_failures:

        ip_address = failure["ip_address"]

        if ip_address == "unknown":
            continue

        if ip_address not in failures_by_ip:

            failures_by_ip[ip_address] = []

        failures_by_ip[ip_address].append(
            failure
        )

    brute_force_ips = []

    for ip_address, failures in (
        failures_by_ip.items()
    ):

        failures.sort(
            key=lambda x: x["timestamp"]
        )

        for i in range(
            len(failures)
        ):

            start_time = datetime.fromisoformat(
                failures[i]["timestamp"]
            )

            count = 1

            for j in range(
                i + 1,
                len(failures)
            ):

                current_time = (
                    datetime.fromisoformat(
                        failures[j]["timestamp"]
                    )
                )

                difference = (
                    current_time -
                    start_time
                ).total_seconds()

                if difference <= time_window:

                    count += 1

                else:

                    break

            if count >= threshold:

                risk_score = 40

                brute_force_ips.append({

                    "alert_type":
                        "BRUTE_FORCE_ATTACK",

                    "risk_score":
                        risk_score,

                    "severity":
                        get_alert_severity(
                            "BRUTE_FORCE_ATTACK"
                        ),

                    "ip_address":
                        ip_address,

                    "failure_count":
                        count,

                    "time_window":
                        time_window
                })

                break

    return brute_force_ips


def display_brute_force(
    brute_force_ips
):

    print()
    print("=" * 60)
    print("BRUTE-FORCE DETECTION")
    print("=" * 60)

    if not brute_force_ips:

        print()
        print(
            "No possible brute-force attacks detected."
        )

    else:

        print()

        for attack in brute_force_ips:

            print(
                "Alert Type :",
                attack["alert_type"]
            )

            print(
                "IP Address :",
                attack["ip_address"]
            )

            print(
                "Failures   :",
                attack["failure_count"]
            )

            print(
                "Risk Score :",
                attack["risk_score"]
            )

            print(
                "Severity   :",
                attack["severity"]
            )

            print(
                "Status     : "
                "POSSIBLE BRUTE-FORCE ATTACK"
            )

            print("-" * 60)

    print()
    print("=" * 60)


def correlate_attack_chains(
    normalized_events,
    brute_force_ips,
    account_compromise_alerts
):

    attack_chains = []

    # --------------------------------------------------
    # Group attack information by IP
    # --------------------------------------------------

    chains_by_ip = {}

    for attack in brute_force_ips:

        ip_address = attack["ip_address"]

        if ip_address not in chains_by_ip:

            chains_by_ip[ip_address] = {
                "ip_address": ip_address,
                "stages": []
            }

        chains_by_ip[ip_address]["stages"].append(
            "AUTHENTICATION_FAILURE"
        )

        chains_by_ip[ip_address]["stages"].append(
            "BRUTE_FORCE_ATTACK"
        )

    # --------------------------------------------------
    # Add successful login only if it occurs after
    # an authentication failure from the same IP
    # within the correlation window
    # --------------------------------------------------

    for event in normalized_events:

        if event["event_type"] != "SUCCESSFUL_LOGIN":
            continue

        ip_address = event["ip_address"]

        if ip_address not in chains_by_ip:
            continue

        login_time = datetime.fromisoformat(
            event["timestamp"]
        )

        failure_found = False

        for failure in normalized_events:

            if failure["event_type"] != "AUTH_FAILURE":
                continue

            if failure["ip_address"] != ip_address:
                continue

            failure_time = datetime.fromisoformat(
                failure["timestamp"]
            )

            difference = (
                login_time - failure_time
            ).total_seconds()

            if 0 <= difference <= 60:

                failure_found = True
                break

        if failure_found:

            chains_by_ip[ip_address]["stages"].append(
                "SUCCESSFUL_LOGIN"
            )

    # --------------------------------------------------
    # Add account compromise only when it is already
    # correlated with the same IP
    # --------------------------------------------------

    for alert in account_compromise_alerts:

        ip_address = alert["ip_address"]

        if ip_address not in chains_by_ip:
            continue

        chains_by_ip[ip_address]["stages"].append(
            "POSSIBLE_ACCOUNT_COMPROMISE"
        )

    # --------------------------------------------------
    # Remove duplicate stages while preserving order
    # --------------------------------------------------

    for chain in chains_by_ip.values():

        unique_stages = []

        for stage in chain["stages"]:

            if stage not in unique_stages:

                unique_stages.append(stage)

        chain["stages"] = unique_stages

        attack_chains.append(chain)

    return attack_chains

def calculate_risk_score(
    event_counts,
    brute_force_ips,
    account_compromise_alerts
):

    risk_score = 0

    # --------------------------------------------------
    # Authentication failures
    # --------------------------------------------------

    auth_failures = event_counts.get(
        "AUTH_FAILURE",
        0
    )

    brute_force_failure_count = 0

    for attack in brute_force_ips:

        brute_force_failure_count += (
            attack["failure_count"]
        )

    independent_failures = max(
        0,
        auth_failures -
        brute_force_failure_count
    )

    risk_score += (
        independent_failures * 10
    )

    # --------------------------------------------------
    # Successful logins
    # --------------------------------------------------

    successful_logins = event_counts.get(
        "SUCCESSFUL_LOGIN",
        0
    )

    compromised_logins = len(
        account_compromise_alerts
    )

    independent_successful_logins = max(
        0,
        successful_logins -
        compromised_logins
    )

    risk_score += (
        independent_successful_logins * 5
    )

    # --------------------------------------------------
    # Brute-force detections
    # --------------------------------------------------

    for attack in brute_force_ips:

        risk_score += attack["risk_score"]

    # --------------------------------------------------
    # Account compromise detections
    # --------------------------------------------------

    for alert in account_compromise_alerts:

        risk_score += alert["risk_score"]

    return risk_score


def get_risk_level(
    total_risk
):

    if total_risk >= 300:

        return "CRITICAL"

    elif total_risk >= 150:

        return "HIGH"

    elif total_risk >= 50:

        return "MEDIUM"

    else:

        return "LOW"


def display_risk_analysis(
    event_counts,
    brute_force_ips,
    account_compromise_alerts
):

    print()
    print("=" * 60)
    print("RISK ANALYSIS")
    print("=" * 60)

    # Event-based risk
    for event, count in (
        event_counts.items()
    ):

        risk_values = {

            "AUTH_FAILURE": 10,

            "SUCCESSFUL_LOGIN": 5
        }

        score = risk_values.get(
            event,
            0
        )

        if score > 0:

            event_risk = (
                score * count
            )

            print(
                "Event       :",
                event
            )

            print(
                "Occurrences :",
                count
            )

            print(
                "Risk/Event  :",
                score
            )

            print(
                "Total Risk  :",
                event_risk
            )

            print("-" * 60)

    # Brute-force risk
    for attack in brute_force_ips:

        print(
            "Event       :",
            "BRUTE_FORCE_ATTACK"
        )

        print(
            "IP Address  :",
            attack["ip_address"]
        )

        print(
            "Failures    :",
            attack["failure_count"]
        )

        print(
            "Risk Score  :",
            attack["risk_score"]
        )

        print(
            "Severity    :",
            attack["severity"]
        )

        print("-" * 60)

    # Account compromise risk
    for alert in (
        account_compromise_alerts
    ):

        print(
            "Event       :",
            "POSSIBLE_ACCOUNT_COMPROMISE"
        )

        print(
            "Username    :",
            alert["username"]
        )

        print(
            "IP Address  :",
            alert["ip_address"]
        )

        print(
            "Risk Score  :",
            alert["risk_score"]
        )

        print(
            "Severity    :",
            alert["severity"]
        )

        print("-" * 60)

    # Final risk
    total_risk = calculate_risk_score(
        event_counts,
        brute_force_ips,
        account_compromise_alerts
    )

    risk_level = get_risk_level(
        total_risk
    )

    print(
        "TOTAL RISK SCORE :",
        total_risk
    )

    print(
        "RISK LEVEL       :",
        risk_level
    )

    print("=" * 60)


def display_attack_chains(
    attack_chains
):

    print()
    print("=" * 60)
    print("ATTACK CHAIN CORRELATION")
    print("=" * 60)

    if not attack_chains:

        print(
            "No attack chains detected."
        )

    else:

        for number, chain in enumerate(
            attack_chains,
            1
        ):

            print(
                "Attack Chain :",
                number
            )

            print(
                "IP Address   :",
                chain["ip_address"]
            )

            print(
                "Stages       :"
            )

            for stage in chain["stages"]:

                print(
                    "  ->",
                    stage
                )

            print("-" * 60)

    print("=" * 60)


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python3 src/log_analyzer.py <log_file>"
        )

        sys.exit(1)

    log_file = sys.argv[1]

    (
        total_logs,
        event_counts,
        auth_failures,
        normalized_events
    ) = analyze_logs(
        log_file
    )

    # --------------------------------------------------
    # Display summary
    # --------------------------------------------------

    display_summary(
        total_logs,
        event_counts
    )

    # --------------------------------------------------
    # Display authentication failures
    # --------------------------------------------------

    display_auth_failures(
        auth_failures
    )

    # --------------------------------------------------
    # Brute force detection
    # --------------------------------------------------

    brute_force_ips = detect_brute_force(
        auth_failures
    )

    display_brute_force(
        brute_force_ips
    )

    # --------------------------------------------------
    # Account compromise detection
    # --------------------------------------------------

    account_compromise_alerts = (
        detect_account_compromise(
            normalized_events
        )
    )

    print()
    print("=" * 60)
    print("POSSIBLE ACCOUNT COMPROMISE")
    print("=" * 60)

    if account_compromise_alerts:

        for alert in account_compromise_alerts:

            print(
                "Alert Type :",
                alert["alert_type"]
            )

            print(
                "Risk Score :",
                alert["risk_score"]
            )

            print(
                "Severity   :",
                alert["severity"]
            )

            print(
                "Username   :",
                alert["username"]
            )

            print(
                "IP Address :",
                alert["ip_address"]
            )

            print(
                "Failed Attempts :",
                alert["failed_attempts"]
            )

            print(
                "Successful Login :",
                alert["successful_login"]
            )

            print(
                "Reason     :",
                alert["reason"]
            )

            print("-" * 60)

    else:

        print(
            "No possible account compromise detected."
        )

    print("=" * 60)

    # --------------------------------------------------
    # Suspicious sudo activity
    # --------------------------------------------------

    suspicious_sudo_alerts = (
        detect_suspicious_sudo(
            normalized_events
        )
    )
    sudo_burst_alerts = detect_sudo_burst(
	suspicious_sudo_alerts
    )
    suspicious_user_creation_alerts =(
detect_suspicious_user_creation(
normalized_events
       )
    )
    print()
    print("=" * 60)
    print("SUSPICIOUS SUDO ACTIVITY")
    print("=" * 60)

    if suspicious_sudo_alerts:

        for alert in suspicious_sudo_alerts:

            print(
                "Alert Type :",
                alert["alert_type"]
            )

            print(
                "Timestamp  :",
                alert["timestamp"]
            )

            print(
                "Username   :",
                alert["username"]
            )

            print(
                "Command    :",
                alert["command"]
            )

            print(
                "Severity   :",
                alert["severity"]
            )

            print(
                "Risk Score :",
                alert["risk_score"]
            )
            print(
    "Reason     :",
    alert["matched_pattern"]
)
            print("-" * 60)

    else:

        print(
            "No suspicious sudo activity detected."
        )

    print("=" * 60)
    print()
    print("=" * 60)
    print("SUSPICIOUS SUDO BURST")
    print("=" * 60)

    if sudo_burst_alerts:

        for alert in sudo_burst_alerts:

            print(
            "Alert Type   :",
            alert["alert_type"]
            )

            print(
            "Username     :",
            alert["username"]
            )

            print(
            "Start Time   :",
            alert["start_time"]
            )

            print(
            "Commands     :",
            alert["command_count"]
            )

            print(
            "Time Window  :",
            alert["time_window"],
            "seconds"
            )

            print(
            "Severity     :",
            alert["severity"]
            )

            print(
            "Risk Score   :",
            alert["risk_score"]
            )

            print("-" * 60)

    else:

        print(
        "No suspicious sudo burst detected."
        )

    print("=" * 60)
    print()
    print("=" * 60)
    print("SUSPICIOUS USER CREATION")
    print("=" * 60)

    if suspicious_user_creation_alerts:

        for alert in suspicious_user_creation_alerts:

            print(
            "Alert Type :",
            alert["alert_type"]
            )

            print(
            "Timestamp  :",
            alert["timestamp"]
            )

            print(
            "Username   :",
            alert["username"]
            )

            print(
            "Severity   :",
            alert["severity"]
            )

            print(
            "Risk Score :",
            alert["risk_score"]
            )

            print(
            "Reason     :",
            alert["reason"]
            )

            print("-" * 60)

    else:

        print(
        "No suspicious user creation detected."
        )

    print("=" * 60)
    # --------------------------------------------------
    # Attack chain correlation
    # --------------------------------------------------

    attack_chains = correlate_attack_chains(
        normalized_events,
        brute_force_ips,
        account_compromise_alerts
    )

    display_attack_chains(
        attack_chains
    )

    # --------------------------------------------------
    # Risk analysis
    # --------------------------------------------------

    risk_score = calculate_risk_score(
        event_counts,
        brute_force_ips,
        account_compromise_alerts
    )

    risk_level = get_risk_level(
        risk_score
    )

    display_risk_analysis(
        event_counts,
        brute_force_ips,
        account_compromise_alerts
    )
