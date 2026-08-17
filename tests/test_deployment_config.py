"""The deployment configuration has to agree with itself.

These tests read `Dockerfile` and `render.yaml` as text, which is unusual for this suite --
everything else asserts on behaviour. The property at stake is not reachable from Python:
it lives in two files that are edited independently, by different people, at different
times, and it is only wrong when they disagree.

It has already cost one deploy. `AEGIS_API_LOG_DATABASE` was set in the Dockerfile *and*
in the Blueprint. Removing it from the Blueprint looked like the whole fix, the image kept
setting it, and the running service reported `log_durable: true` on a free instance with no
disk -- claiming exactly the property it had just lost, which is the failure this project
exists to argue against.

Same shape as F1 in the classifier: one rule written twice, in two modules, required to
agree, and both copies wrong in the same way because nobody compared them. There the fix
was to delete the duplicate. Here the two files genuinely serve different purposes, so the
duplicate cannot be deleted -- which leaves asserting the invariant as the next best thing.

Parsed by scanning lines rather than with a YAML library on purpose: `pyyaml` is in the
optional `[agentdojo]` extra, not `[dev]`, and a guard that silently skips in CI because a
dependency is missing is not a guard.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOG_DATABASE = "AEGIS_API_LOG_DATABASE"


def _active_lines(text: str) -> list[str]:
    """Lines with comments and blanks removed.

    A commented-out setting is documentation, not configuration, and the whole point here
    is to distinguish the two -- `render.yaml` deliberately keeps the durable-log settings
    as commented guidance for whoever upgrades the plan later.
    """
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if line.strip():
            out.append(line)
    return out


def test_the_image_does_not_configure_a_durable_log_path() -> None:
    """The image must not claim durability on behalf of a deployment it cannot see.

    A container cannot tell whether `/data` is a persistent disk or ephemeral scratch. If
    the image sets the database path anyway, every deployment inherits a service reporting
    `log_durable: true`, including the ones where it is false.
    """
    dockerfile = (REPO / "Dockerfile").read_text(encoding="utf-8")
    offenders = [ln for ln in _active_lines(dockerfile) if LOG_DATABASE in ln]
    assert not offenders, (
        f"Dockerfile sets {LOG_DATABASE}: {offenders}. An image cannot know whether a "
        "volume was mounted, so setting this makes /health report durability that the "
        "deployment may not have. Let the deployment set it."
    )


def test_the_blueprint_only_configures_a_log_path_when_it_provides_a_disk() -> None:
    """The three settings move together, or the deployment lies about its own history.

    A configured path with no disk behind it is strictly worse than no path at all: SQLite
    works, `/health` reports durable, and the log silently restarts. This is the assertion
    that would have caught the broken deploy before it shipped.
    """
    blueprint = _active_lines((REPO / "render.yaml").read_text(encoding="utf-8"))

    sets_path = any(LOG_DATABASE in ln for ln in blueprint)
    declares_disk = any(ln.strip().startswith("disk:") for ln in blueprint)

    if sets_path:
        assert declares_disk, (
            f"render.yaml sets {LOG_DATABASE} without a `disk:` block. The path would "
            "point at ephemeral container storage, and the service would report "
            "log_durable: true while losing its history on every restart."
        )


def test_a_declared_disk_is_not_paired_with_a_plan_that_cannot_hold_one() -> None:
    """Render's free instances cannot attach a persistent disk.

    Declaring one on `plan: free` fails at apply time; declaring one and forgetting to
    raise the plan is the reverse mistake, and it bills for an instance whose disk never
    attached. Either way the two lines have to be read together.
    """
    blueprint = _active_lines((REPO / "render.yaml").read_text(encoding="utf-8"))

    declares_disk = any(ln.strip().startswith("disk:") for ln in blueprint)
    free_plan = any(ln.strip() == "plan: free" for ln in blueprint)

    assert not (declares_disk and free_plan), (
        "render.yaml declares a `disk:` on `plan: free`. Free instances cannot attach a "
        "persistent disk; the plan and the disk move together."
    )


def test_the_upgrade_path_is_still_written_down_where_it_is_needed() -> None:
    """Removing the setting must not remove the knowledge of how to restore it.

    The failure this file guards against was caused by a value living in two places. The
    obvious overcorrection is to delete every mention, which leaves the next person to
    rediscover that durability needs a plan, a disk and a path in agreement.
    """
    blueprint = (REPO / "render.yaml").read_text(encoding="utf-8")
    assert LOG_DATABASE in blueprint, (
        "render.yaml no longer mentions "
        f"{LOG_DATABASE} even in a comment. The upgrade path has to stay documented "
        "where the plan and the disk are configured."
    )


def _copied_sources(dockerfile: str) -> list[str]:
    """Local paths the Dockerfile copies into the image, ignoring --from=builder stages."""
    sources = []
    for line in _active_lines(dockerfile):
        if not line.upper().startswith("COPY "):
            continue
        parts = line.split()[1:]
        if any(p.startswith("--from=") for p in parts):
            continue
        parts = [p for p in parts if not p.startswith("--")]
        sources.extend(parts[:-1])
    return sources


def test_the_image_can_actually_receive_everything_it_copies() -> None:
    """`.dockerignore` must not silently empty a `COPY` the Dockerfile performs.

    This has happened. `COPY results /app/results` was added for the /v1/real-model
    endpoint while `.dockerignore` still excluded `results/`. Nothing failed: the build
    succeeded, the endpoint deployed, and it reported `measured: false` in production
    forever, which reads as "nobody has run the sweep" rather than "the data was never
    shipped".

    Same shape as the two files that had to agree about the log database path, and the same
    reason it is asserted here rather than trusted: the failure is silent by construction,
    because an ignored source is not an error.
    """
    dockerfile = (REPO / "Dockerfile").read_text(encoding="utf-8")
    ignore_path = REPO / ".dockerignore"
    if not ignore_path.exists():
        return

    ignored = _active_lines(ignore_path.read_text(encoding="utf-8"))
    excluded = {line.rstrip("/") for line in ignored if not line.startswith("!")}
    reincluded = {line[1:] for line in ignored if line.startswith("!")}

    for source in _copied_sources(dockerfile):
        top = source.strip("./").split("/")[0]
        if not top or top in {".", "*"}:
            continue
        # `results/*` excludes the contents; `!results/*.json` puts them back. A bare
        # `results` exclusion with no re-inclusion is the broken case.
        blocked = top in excluded or f"{top}/*" in excluded
        rescued = any(rule.startswith(f"{top}/") for rule in reincluded)
        assert not blocked or rescued, (
            f"Dockerfile copies {source!r} but .dockerignore excludes {top!r} with no "
            f"re-inclusion. The build will succeed and the image will not contain it."
        )
