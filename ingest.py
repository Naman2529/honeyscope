"""Load Cowrie JSON logs into DuckDB.

Usage:
    python ingest.py --exclude-ip 136.233.9.107

Reads every data/raw/cowrie.json* file (Cowrie rotates daily), rebuilds the
`events` table from scratch, then builds the `sessions` view from sql/sessions.sql.
Safe to re-run any time you pull fresh logs.
"""
import argparse
import glob
import json
from pathlib import Path

import duckdb
import pandas as pd

ROOT = Path(__file__).parent
RAW_GLOB = str(ROOT / "data" / "raw" / "cowrie.json*")
DB_PATH = ROOT / "data" / "honeyscope.duckdb"

# Fields we pull out of each event. Anything else stays in `raw`.
FIELDS = [
    "eventid", "session", "src_ip", "src_port", "dst_port",
    "username", "password", "input", "version", "hassh",
    "url", "shasum", "outfile", "duration_ms", "duration", "message",
]


def load_events(exclude_ips):
    rows, bad = [], 0
    files = sorted(glob.glob(RAW_GLOB))
    if not files:
        raise SystemExit(f"No log files matched {RAW_GLOB} - did you rsync them?")
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1  # partial line at the end of a file being written
                    continue
                if ev.get("src_ip") in exclude_ips:
                    continue
                row = {k: ev.get(k) for k in FIELDS}
                row["ts"] = ev.get("timestamp")
                row["raw"] = line
                rows.append(row)
    df = pd.DataFrame(rows, columns=["ts", *FIELDS, "raw"])
    df = df.drop_duplicates(subset="raw")  # same line pulled twice -> count once
    df["ts"] = pd.to_datetime(df["ts"], utc=True, format="ISO8601")
    # Cowrie 3.x logs duration_ms; older versions log `duration` in seconds.
    df["duration_s"] = pd.to_numeric(df["duration_ms"], errors="coerce") / 1000
    df["duration_s"] = df["duration_s"].fillna(pd.to_numeric(df["duration"], errors="coerce"))
    df = df.drop(columns=["duration_ms", "duration"])
    for col in ["src_port", "dst_port"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
    return df, len(files), bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exclude-ip", action="append", default=[],
                    help="Your own IP(s) - test sessions to drop. Repeatable.")
    args = ap.parse_args()

    df, n_files, bad = load_events(set(args.exclude_ip))
    con = duckdb.connect(str(DB_PATH))
    con.execute("SET TimeZone = 'UTC'")
    con.execute("CREATE OR REPLACE TABLE events AS SELECT * FROM df")
    con.execute((ROOT / "sql" / "sessions.sql").read_text())

    n_ev = con.execute("SELECT count(*) FROM events").fetchone()[0]
    n_sess, n_ips, n_in = con.execute(
        "SELECT count(*), count(DISTINCT src_ip), count(*) FILTER (WHERE login_success) FROM sessions"
    ).fetchone()
    print(f"files={n_files} events={n_ev} bad_lines={bad}")
    print(f"sessions={n_sess} unique_ips={n_ips} sessions_that_logged_in={n_in}")
    print(con.execute(
        "SELECT eventid, count(*) n FROM events GROUP BY 1 ORDER BY 2 DESC"
    ).df().to_string(index=False))


if __name__ == "__main__":
    main()
