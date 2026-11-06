"""Ownership labels and cleanup for the containers the pipeline starts.

Compilation and verification each run in a throw-away container that the agent
removes in a ``finally`` block.  That block never runs if the agent process is
killed (SIGKILL, OOM, a hard ``--purge``-style restart), so the containers keep
running — holding CPU, memory and a bind mount — until something else removes
them.  Every container the pipeline creates therefore carries a label, and this
module removes leftovers that no longer belong to a live run.
"""
import os
from typing import Dict, Optional

import docker
from docker.errors import APIError, DockerException, NotFound

# Label attached to every container the pipeline starts.
OWNER_LABEL = "verivul.owner"
OWNER_VALUE = "verivul"
# PID of the process that created the container, so a cleanup pass can tell a
# leftover from a container belonging to a concurrently running agent.
CREATOR_PID_LABEL = "verivul.creator_pid"
ROLE_LABEL = "verivul.role"

# Labels used before the project was renamed from approxvul.  Cleanup still looks
# for these so containers started by a process that predates the rename are not
# orphaned; nothing writes them any more.
LEGACY_LABEL_SETS = (
    ("approxvul.owner", "approxvul", "approxvul.creator_pid", "approxvul.role"),
)


def _label_sets():
    """Yield ``(owner_label, owner_value, pid_label, role_label)`` for current + classic labels."""
    yield (OWNER_LABEL, OWNER_VALUE, CREATOR_PID_LABEL, ROLE_LABEL)
    for classic in LEGACY_LABEL_SETS:
        yield classic


def container_labels(role: str) -> Dict[str, str]:
    """Return the label set to attach to a container started for *role*."""
    return {
        OWNER_LABEL: OWNER_VALUE,
        ROLE_LABEL: role,
        CREATOR_PID_LABEL: str(os.getpid()),
    }


def reclaim_trap(mount_path: str) -> str:
    """Return a bash ``trap`` line that hands a bind mount back to the host user.

    Containers run as root, so anything they create inside a bind-mounted host
    directory is root-owned.  Root-owned *files* are still removable (the host
    temp dir itself belongs to the user), but a root-owned *subdirectory* is not:
    the user has no write permission inside it, and Python's TemporaryDirectory
    cleanup then fails twice over —

        PermissionError: [Errno 13] Permission denied: '.gitignore'
        PermissionError: [Errno 1] Operation not permitted: '/tmp/tmpXXXX/.mypy_cache'

    — because its fallback tries to chmod a directory the user does not own.
    ESBMC's Python frontend runs mypy, which creates exactly such a directory.

    Chowning the mount back on container exit makes host-side cleanup always
    possible, whether the command succeeded or failed.  A container killed on
    timeout never runs its trap, so callers should still pass
    ``ignore_cleanup_errors=True``.
    """
    return (
        f"trap 'chown -R {os.getuid()}:{os.getgid()} {mount_path} "
        f">/dev/null 2>&1 || true' EXIT\n"
    )


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but is not ours
    return True


def remove_stale_containers(log, include_running: bool = True) -> int:
    """Remove pipeline containers whose creating process is gone.

    Containers created by a still-running process are left alone, so this is safe
    to call at start-up while other agents are working.  Returns the number of
    containers removed.
    """
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as e:
        log.warning(f"Skipping stale-container cleanup — Docker unavailable: {e}")
        return 0

    containers = {}
    for owner_label, owner_value, pid_label, role_label in _label_sets():
        try:
            for container in client.containers.list(
                all=True, filters={"label": f"{owner_label}={owner_value}"}
            ):
                containers[container.id] = (container, pid_label, role_label)
        except APIError as e:
            log.warning(f"Could not list pipeline containers ({owner_label}): {e}")

    removed = 0
    for container, pid_label, role_label in containers.values():
        labels = container.labels or {}
        creator_pid = labels.get(pid_label)
        if creator_pid and creator_pid.isdigit() and _pid_alive(int(creator_pid)):
            continue  # a live agent owns this one
        if not include_running and container.status == "running":
            continue
        try:
            container.remove(force=True)
            removed += 1
            log.info(
                f"Removed stale container {container.name} "
                f"(role={labels.get(role_label, '?')}, status={container.status})"
            )
        except NotFound:
            pass
        except APIError as e:
            log.warning(f"Could not remove stale container {container.name}: {e}")

    if removed:
        log.info(f"Stale-container cleanup removed {removed} container(s).")
    else:
        log.debug("Stale-container cleanup found nothing to remove.")
    return removed


def remove_own_containers(log, pid: Optional[int] = None) -> int:
    """Remove every container created by *pid* (defaults to this process).

    Called from an agent's shutdown path so a SIGTERM does not leave containers
    behind even when the work was interrupted mid-run.
    """
    pid = os.getpid() if pid is None else pid
    try:
        client = docker.from_env()
        containers = client.containers.list(
            all=True,
            filters={"label": [f"{OWNER_LABEL}={OWNER_VALUE}", f"{CREATOR_PID_LABEL}={pid}"]},
        )
    except DockerException as e:
        log.warning(f"Could not enumerate own containers for cleanup: {e}")
        return 0

    removed = 0
    for container in containers:
        try:
            container.remove(force=True)
            removed += 1
        except NotFound:
            pass
        except APIError as e:
            log.warning(f"Could not remove container {container.name}: {e}")
    if removed:
        log.info(f"Removed {removed} container(s) created by pid {pid} during shutdown.")
    return removed
