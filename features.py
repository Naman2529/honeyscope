"""Step 3: detection rules + severity score + ML features.

Usage:
    python features.py

Reads the `sessions` view, adds rule flags / severity / session type / numeric
features, and writes them to the `session_features` table. Run after ingest.py.
"""
import re
from pathlib import Path

import duckdb
import pandas as pd

DB_PATH = Path(__file__).parent / "data" / "honeyscope.duckdb"

# ---------------------------------------------------------------------------
# Detection rules: name -> (regex over the session's commands, severity weight)
# Weights reflect how much an analyst should care if the rule fires.
# ---------------------------------------------------------------------------
RULES = {
    # looking around before deciding what to do with the box
    "recon":        (r"\buname\b|/proc/cpuinfo|\bnproc\b|\blscpu\b|\bfree\b|\bwhoami\b|\bid\b|/etc/passwd|\bw\b$", 1),
    # pulling a payload from the internet
    "download":     (r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b", 3),
    # making a file executable
    "make_exec":    (r"chmod\s+(\+x|[0-7]*7[0-7]*)", 3),
    # piping a download straight into a shell, e.g. curl x | sh
    "pipe_to_shell": (r"(wget|curl)[^;|]*\|\s*(ba)?sh", 4),
    # hidden/obfuscated payloads
    "obfuscation":  (r"base64\s+-d|base64\s+--decode|\\x[0-9a-f]{2}", 3),
    # staying on the box after reboot / coming back later
    "persistence":  (r"crontab|authorized_keys|/etc/rc\.local|systemctl\s+enable|\.bashrc|/etc/init\.d", 5),
    # changing the password so the real owner (and other bots) are locked out
    "cred_change":  (r"\bpasswd\b|\bchpasswd\b", 3),
    # covering tracks / killing competition
    "evasion":      (r"history\s+-c|unset\s+HISTFILE|\bpkill\b|\bkill\s+-9\b|\biptables\b|rm\s+-rf\s+/(tmp|var)", 3),
    # crypto-miners
    "miner":        (r"xmrig|minerd|stratum\+tcp|cryptonight|monero|\.xmr", 5),
    # IoT botnet tooling (Mirai family loves busybox)
    "botnet":       (r"\bbusybox\b|mirai|\bdvrHelper\b", 3),
}
COMPILED = {name: re.compile(rx, re.IGNORECASE) for name, (rx, _) in RULES.items()}


def apply_rules(df):
    cmds = df["commands"].fillna("")
    for name, rx in COMPILED.items():
        df[f"rule_{name}"] = cmds.apply(lambda c, rx=rx: bool(rx.search(c)))
    # Cowrie actually caught a file transfer - stronger signal than the regex alone
    df["rule_file_transfer"] = df["n_file_transfers"] > 0
    return df


def severity(row):
    score = sum(w for name, (_, w) in RULES.items() if row[f"rule_{name}"])
    score += 4 if row["rule_file_transfer"] else 0
    score += 1 if row["login_success"] else 0
    return score


def tier(score, login_success):
    if not login_success:
        return "noise"       # never got in - scanners and failed brute force
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def session_type(row):
    """What kind of visitor was this? Plain-English bucket for charts/README."""
    if row["n_password_attempts"] == 0 and row["n_pubkey_attempts"] == 0:
        return "scanner"           # connected, never tried to log in
    if not row["login_success"]:
        return "brute_force"       # tried passwords, never got in
    if row["n_commands"] == 0:
        return "login_only"        # got in, did nothing (checking creds work)
    return "interactive"           # got in and ran commands


def main():
    con = duckdb.connect(str(DB_PATH))
    con.execute("SET TimeZone = 'UTC'")
    df = con.execute("SELECT * FROM sessions").df()
    if df.empty:
        raise SystemExit("sessions is empty - run ingest.py first (without excluding your IP to test)")

    df = apply_rules(df)
    df["severity"] = df.apply(severity, axis=1)
    df["tier"] = df.apply(lambda r: tier(r["severity"], r["login_success"]), axis=1)
    df["session_type"] = df.apply(session_type, axis=1)

    # numeric features for the ML step
    df["cmd_chars"] = df["commands"].fillna("").str.len()
    df["n_rules_fired"] = df[[c for c in df.columns if c.startswith("rule_")]].sum(axis=1)
    df["login_success_int"] = df["login_success"].astype(int)

    con.execute("CREATE OR REPLACE TABLE session_features AS SELECT * FROM df")

    print(f"sessions={len(df)}\n")
    print("session types:\n" + df["session_type"].value_counts().to_string() + "\n")
    print("tiers:\n" + df["tier"].value_counts().to_string() + "\n")
    fired = {c[5:]: int(df[c].sum()) for c in df.columns if c.startswith("rule_")}
    print("rules fired:\n" + "\n".join(f"  {k:<14}{v}" for k, v in fired.items() if v))
    print("\ntop 5 by severity:")
    cols = ["session", "src_ip", "severity", "tier", "commands"]
    print(df.sort_values("severity", ascending=False)[cols].head(5).to_string(index=False, max_colwidth=60))


if __name__ == "__main__":
    main()
