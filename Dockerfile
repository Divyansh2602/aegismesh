# The API, containerised.
#
# Two stages so the runtime image carries no build toolchain and no dev dependencies. The
# runtime runs as a non-root user with a read-only-by-default layout: the only writable
# path is the volume the transparency log lives on, which is the one thing that genuinely
# must survive a restart.

# ---------------------------------------------------------------------------- builder
FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Dependency metadata first, so a source-only change reuses the cached install layer.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY aegis ./aegis

# --prefix rather than a venv: the result is a plain tree that copies cleanly into the
# runtime stage without carrying absolute paths that only resolve in the builder.
RUN pip install --prefix=/install .

# ---------------------------------------------------------------------------- runtime
FROM python:3.13-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/local/bin:${PATH}"

# A non-root account with no login shell. The API executes attacker-supplied *text*, never
# attacker-supplied code, but the whole argument of this project is that defence in depth
# beats trusting one boundary — running as root because nothing is known to escape would
# be the same reasoning it criticises.
RUN useradd --system --create-home --shell /usr/sbin/nologin aegis

COPY --from=builder /install /usr/local
COPY --chown=aegis:aegis aegis /app/aegis
COPY --chown=aegis:aegis tools /app/tools

# The transparency log's database lives here. Mount a persistent disk at this path, or the
# log resets on every restart and the one property a returning visitor can test personally
# — that the tree grew and still verifies against the head they were given — is gone.
RUN mkdir -p /data && chown aegis:aegis /data
VOLUME ["/data"]

WORKDIR /app
USER aegis

ENV AEGIS_API_LOG_DATABASE=/data/aegis-log.sqlite3 \
    PORT=8000

EXPOSE 8000

# $PORT because the platform assigns it; the default above keeps `docker run` working
# locally with no arguments.
#
# JSON form wrapping an explicit `sh -c` rather than bare shell form. Both expand the
# variable, but bare shell form leaves `sh` as PID 1, which swallows SIGTERM — the
# container would then be killed rather than shut down, and uvicorn would never close its
# open SSE streams. `exec` replaces the shell so uvicorn *is* PID 1 and receives the signal.
CMD ["sh", "-c", "exec uvicorn aegis.api.app:app --host 0.0.0.0 --port ${PORT}"]
