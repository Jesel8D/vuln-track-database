#!/usr/bin/env python3
"""Independent fresh-bootstrap smoke. Creates only its own tmpfs container, no URLs."""
import os
import secrets
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = (
    "postgres:16.15-alpine@sha256:"
    "0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab"
)
NAME = "vulntrack-mvp-b-test-" + secrets.token_hex(6)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def sql(source):
    return run("docker", "exec", "-i", NAME, "psql", "-Xq", "-U", "postgres",
               "-v", "ON_ERROR_STOP=1", input=source).stdout


print("Fresh bootstrap disposable:", NAME, flush=True)
try:
    run("docker", "run", "-d", "--name", NAME, "--network", "none",
        "--label", "vulntrack.disposable=true", "--tmpfs", "/var/lib/postgresql/data:rw",
        "--mount", f"type=bind,source={ROOT}/init,target=/docker-entrypoint-initdb.d,readonly",
        "--mount", f"type=bind,source={ROOT}/sql,target=/vulntrack/sql,readonly",
        "-e", "POSTGRES_PASSWORD", "-e", "VULNTRACK_SCHEMA=mvp-b", IMAGE,
        env={**os.environ, "POSTGRES_PASSWORD": secrets.token_urlsafe(32)})
    for _ in range(90):
        result = subprocess.run(["docker", "exec", NAME, "pg_isready", "-h", "127.0.0.1",
                                 "-U", "postgres"], capture_output=True, check=False)
        if result.returncode == 0:
            break
        time.sleep(.5)
    else:
        raise RuntimeError("Disposable PostgreSQL did not start")
    # The unchanged V1 demo seed belongs before MVP-B's ingestion guards.
    # Fresh production bootstrap has no fabricated legacy rows or default accounts.
    sql("DO $$ BEGIN IF (SELECT count(*) FROM vulntrack.assets) <> 0 THEN RAISE EXCEPTION 'Expected empty inventory'; END IF; END $$;")
    output=sql((ROOT / "tests/003_mvp_cve.sql").read_text())
    print(output.strip(), flush=True)
    print("Fresh entrypoint MVP-B + empty inventory passed; no port/volume/network.")
except subprocess.CalledProcessError as exc:
    # No env, credentials or raw SQL/values in errors.
    raise SystemExit(f"Disposable database check failed (exit {exc.returncode})") from None
finally:
    subprocess.run(["docker", "stop", "--time", "10", NAME], capture_output=True, check=False)
    print("Stopped own disposable container:", NAME, flush=True)
