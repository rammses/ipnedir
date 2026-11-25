"""CI-only GitHub artifact and release-control validation; not an app dependency."""

import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import time
import zipfile


def gh_get(endpoint, limit):
    """Read-only API call, with a 60s execution/EOF deadline and bounded bytes."""
    return _run_bounded(
        ["gh", "api", "--method", "GET", "-H", "X-GitHub-Api-Version: 2026-03-10", endpoint],
        limit,
        60,
    )


def verify_subject(subject, name):
    def positive(value):
        return type(value) is int and value > 0

    if (not isinstance(subject, dict) or not positive(subject["id"])
            or subject["name"] != name or subject["expired"] is not False):
        raise ValueError("invalid artifact identity/state")
    if not positive(subject["size_in_bytes"]) or subject["size_in_bytes"] > 140 * 1024 * 1024:
        raise ValueError("artifact size out of bounds")
    digest = subject["digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("missing/invalid server artifact digest")
    run = subject["workflow_run"]
    for key, expected in [
        ("id", int(os.environ["GITHUB_RUN_ID"])),
        ("repository_id", int(os.environ["GITHUB_REPOSITORY_ID"])),
        ("head_repository_id", int(os.environ["GITHUB_REPOSITORY_ID"])),
    ]:
        if not positive(run[key]) or run[key] != expected:
            raise ValueError("artifact belongs to another run/repository")
    if run["head_sha"] != os.environ["GITHUB_SHA"]:
        raise ValueError("artifact source SHA mismatch")
    return subject["id"], digest.removeprefix("sha256:")


def extract_zip(path, digest, destination, expected):
    expected = set(expected)
    if (not expected or len(expected) > 9
            or any(not re.fullmatch(r"[A-Za-z0-9._-]+", name) or ".." in name for name in expected)):
        raise ValueError("unsafe expected filenames")

    def limit_for(name):
        return 32 * 1024 * 1024 if name.endswith(".tar.gz") else 4096

    bound = sum(limit_for(name) for name in expected) + 1024 * 1024
    if not path.is_file() or path.is_symlink() or path.stat().st_size > bound:
        raise ValueError("ZIP exceeds size bound")
    with path.open("rb") as stream:
        hasher = hashlib.sha256()
        count = 0
        while chunk := stream.read(65536):
            count += len(chunk)
            if count > bound:
                raise ValueError("ZIP grew beyond size bound")
            hasher.update(chunk)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or hasher.hexdigest() != digest:
            raise ValueError("ZIP server digest mismatch")
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            entries = archive.infolist()
            if len(entries) != len(expected) or {e.filename for e in entries} != expected:
                raise ValueError("missing/duplicate/unexpected ZIP member")
            payloads = {}
            for entry in entries:
                if (entry.is_dir() or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                        or entry.flag_bits & 1):
                    raise ValueError("ZIP member is not a plain regular file")
                limit = limit_for(entry.filename)
                if not 0 < entry.file_size <= limit:
                    raise ValueError("ZIP member size out of bounds")
                with archive.open(entry) as member:
                    data = member.read(limit + 1)
                if len(data) != entry.file_size or len(data) > limit:
                    raise ValueError("invalid ZIP decompression size")
                payloads[entry.filename] = data
    for part in [destination, *destination.absolute().parents]:
        if part.is_symlink():
            raise ValueError("symlink destination")
    if any((destination / name).exists() or (destination / name).is_symlink() for name in expected):
        raise ValueError("candidate overwrite forbidden")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    created = []
    try:
        for name, data in payloads.items():
            with (destination / name).open("xb") as output:
                created.append(destination / name)
                output.write(data)
    except BaseException:
        for name in created:
            name.unlink()
        raise


def require_protection(data):
    """Validate the actual server response; the workflow still owns the GET/gate."""
    if (not isinstance(data, dict) or type(data["id"]) is not int
            or data["id"] <= 0 or data["name"] != "release"):
        raise ValueError("invalid environment identity")
    expected = f"https://api.github.com/repos/{os.environ['GITHUB_REPOSITORY']}/environments/release"
    if data["url"] != expected:
        raise ValueError("environment belongs to another source")
    rules = data["protection_rules"]
    if (not isinstance(rules, list)
            or any(not isinstance(r, dict) or type(r["id"]) is not int or r["id"] <= 0
                   or not isinstance(r["type"], str) for r in rules)):
        raise ValueError("invalid environment protection schema")
    required = [r for r in rules if r["type"] == "required_reviewers"]
    if len(required) != 1:
        raise ValueError("owner-configured required reviewers are mandatory; environment name alone is NOT protection")
    rule = required[0]
    if type(rule["prevent_self_review"]) is not bool:
        raise ValueError("invalid reviewer rule schema")
    reviewers = rule["reviewers"]
    if not isinstance(reviewers, list) or not 1 <= len(reviewers) <= 6:
        raise ValueError("required reviewers are empty/invalid")
    for entry in reviewers:
        if entry["type"] not in ("User", "Team"):
            raise ValueError("invalid reviewer kind")
        reviewer = entry["reviewer"]
        if type(reviewer["id"]) is not int or reviewer["id"] <= 0:
            raise ValueError("invalid reviewer id")
        identity = reviewer["login"] if entry["type"] == "User" else reviewer["slug"]
        if not isinstance(identity, str) or not identity:
            raise ValueError("missing reviewer identity")
    print("Actual server response has required-reviewer protection; owner approval remains a GitHub environment gate")


def _run_bounded(command, limit, timeout):
    # Selectors/nonblocking reads bound EOF draining as well as execution; no
    # reader threads or timer callback outlive the operation. Python 3.10 APIs.
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, start_new_session=True,
    )
    assert process.stdout is not None  # Popen's stdout=PIPE ownership contract.
    try:
        os.set_blocking(process.stdout.fileno(), False)
        data = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("GitHub GET timed out including pipe drain")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, min(65536, limit + 1 - len(data)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        data.extend(chunk)
                        if len(data) > limit:
                            raise ValueError("GitHub response exceeds bound")
        # Do not poll/reap before EOF: the waitable child reserves its session /
        # process-group ID until cleanup, even if it exited ahead of a holder.
        if process.wait(timeout=max(0, deadline - time.monotonic())) != 0:
            raise ValueError("GitHub GET failed; permission/schema errors block")
        return bytes(data)
    except subprocess.TimeoutExpired as error:
        raise ValueError("GitHub GET timed out") from error
    finally:
        try:
            if process.returncode is None:
                # start_new_session owns exactly this group. The direct child
                # has not been reaped, so never signal a recycled/unrelated ID.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        finally:
            process.stdout.close()
