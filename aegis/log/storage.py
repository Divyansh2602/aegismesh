"""Durable backing for the transparency log.

A log that forgets on restart demonstrates nothing. The entire claim of an append-only
log is a property *over time*, and the only person who has genuinely tested it is a
visitor who returns tomorrow and takes a consistency proof against the head they were
shown today. That is impossible if the tree resets whenever the host sleeps, which is
why storage lands with the public API rather than being deferred to deployment.

**What durability is, and what it is not.** Persisting the entries makes the tree
survive a restart and makes every leaf recomputable from what was stored. It does not
make the store tamper-proof: whoever can write this database can rewrite a row and its
stored leaf together, and no check inside the storage layer can tell. Tamper-*evidence*
comes from somewhere the operator does not control -- an independent witness in another
trust domain holding a root it will not retract (``aegis.log.witness``). The integrity
check below catches corruption, not an adversary, and it is documented that way so
nobody mistakes it for the security property.

There is deliberately no update and no delete anywhere in this module.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Protocol

from aegis.log import merkle


class LogCorrupted(RuntimeError):
    """Stored entries do not reconstruct the tree they were stored as."""


class LogStorage(Protocol):
    """Append-only durable backing for :class:`~aegis.log.log.TransparencyLog`."""

    def load(self) -> list[bytes]:
        """Every stored entry, in index order."""
        ...

    def append(self, index: int, entry: bytes, leaf: bytes) -> None:
        """Persist one entry at ``index``, which must be the next free index."""
        ...


class InMemoryLogStorage:
    """The default, preserving the log's pre-Phase-5 behaviour exactly.

    Kept as a real implementation of the protocol rather than as a ``None`` branch
    inside the log, so the durable path and the ephemeral path are the same code with a
    different backing and the tests can hold both to the same assertions.
    """

    def __init__(self) -> None:
        self._entries: list[bytes] = []

    def load(self) -> list[bytes]:
        return list(self._entries)

    def append(self, index: int, entry: bytes, leaf: bytes) -> None:
        if index != len(self._entries):
            raise LogCorrupted(f"append at index {index}, expected {len(self._entries)}")
        self._entries.append(entry)


class SqliteLogStorage:
    """SQLite backing for a single-process log.

    SQLite rather than a database server because the deployment is one process serving
    one log, and the RFC 6962 implementation this backs was hand-written precisely so a
    reviewer could check it in an afternoon. Pairing it with storage that needs its own
    service would spend the readability that was the whole point.

    ``idx`` is the primary key and every write is a plain ``INSERT``. A second writer
    racing to the same index gets an ``IntegrityError`` from the database rather than
    silently overwriting a leaf, so append-only is enforced by the schema rather than by
    convention.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS log_entries (
            idx   INTEGER PRIMARY KEY,
            entry BLOB NOT NULL,
            leaf  BLOB NOT NULL
        )
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False because a FastAPI worker thread may not be the thread
        # that opened the connection. The lock below is what actually serializes writes;
        # relying on SQLite's own locking would surface as a runtime error under load
        # rather than as a wait.
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self._connection.execute("PRAGMA journal_mode=WAL")
        with self._connection:
            self._connection.execute(self._SCHEMA)

    def load(self) -> list[bytes]:
        rows = self._connection.execute(
            "SELECT idx, entry, leaf FROM log_entries ORDER BY idx"
        ).fetchall()

        entries: list[bytes] = []
        for position, (index, entry, leaf) in enumerate(rows):
            if index != position:
                raise LogCorrupted(
                    f"entry index {index} found at position {position}: the log has a gap"
                )
            if merkle.leaf_hash(entry) != leaf:
                raise LogCorrupted(f"entry {index} does not hash to its stored leaf")
            entries.append(entry)
        return entries

    def append(self, index: int, entry: bytes, leaf: bytes) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO log_entries (idx, entry, leaf) VALUES (?, ?, ?)",
                (index, entry, leaf),
            )

    def close(self) -> None:
        self._connection.close()
