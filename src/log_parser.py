import re


def parse_log_line(line):
    pattern = r'^(\S+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$'

    match = re.match(pattern, line)

    if not match:
        return None

    timestamp, hostname, process, pid, message = match.groups()

    return {
        "timestamp": timestamp,
        "hostname": hostname,
        "process": process,
        "pid": pid,
        "message": message
    }
def parse_log_file(file_path):
    parsed_logs = []

    with open(file_path, "r") as log_file:
        for line in log_file:
            result = parse_log_line(line)

            if result:
                parsed_logs.append(result)

    return parsed_logs
