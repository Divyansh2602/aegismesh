"""The log's durability, and the honest limits of it."""

from __future__ import annotations

import sqlite3

import pytest

from aegis.log import merkle
from aegis.log.log import TransparencyLog, decode_hash, verify_receipt
from aegis.log.storage import InMemoryLogStorage, LogCorrupted, SqliteLogStorage
from aegis.warrant.keys import SigningKey

LOG_ID = "did:web:log.aegismesh.example"


def document(n: int) -> dict:
    return {"id": f"urn:uuid:{n:08d}", "credentialSubject": {"n": n}}


@pytest.fixture
def log_key() -> SigningKey:
    return SigningKey.from_seed("aegis-storage-test")


class TestInMemoryStorageIsTheOldBehaviour:
    def test_a_log_with_no_storage_argument_still_works(self, log_key):
        log = TransparencyLog(log_id=LOG_ID, signing_key=log_key)
        assert isinstance(log.storage, InMemoryLogStorage)
        receipt = log.append(document(1))
        assert verify_receipt(document(1), receipt, decode_hash(receipt.root_hash))

    def test_it_refuses_an_append_at_the_wrong_index(self):
        storage = InMemoryLogStorage()
        storage.append(0, b"a", merkle.leaf_hash(b"a"))
        with pytest.raises(LogCorrupted):
            storage.append(0, b"b", merkle.leaf_hash(b"b"))


class TestTheTreeSurvivesARestart:
    def test_reopening_the_database_reproduces_the_same_root(self, tmp_path, log_key):
        path = tmp_path / "log.sqlite3"
        first = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        for n in range(5):
            first.append(document(n))
        root, size = first.root(), first.tree_size
        first.storage.close()

        second = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        assert second.tree_size == size
        assert second.root() == root

    def test_an_old_receipt_still_verifies_after_a_restart(self, tmp_path, log_key):
        """The point of durability: a proof handed out yesterday is still checkable."""
        path = tmp_path / "log.sqlite3"
        first = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        first.append(document(0))
        receipt = first.append(document(1))
        first.storage.close()

        second = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        assert verify_receipt(document(1), receipt, decode_hash(receipt.root_hash))
        assert second.receipt_for(1).root_hash == receipt.root_hash

    def test_a_consistency_proof_bridges_two_sessions(self, tmp_path, log_key):
        """The artifact a returning visitor can actually take: yesterday's head to today's."""
        path = tmp_path / "log.sqlite3"
        first = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        for n in range(3):
            first.append(document(n))
        old_root, old_size = first.root(), first.tree_size
        first.storage.close()

        second = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        for n in range(3, 7):
            second.append(document(n))

        proof = [decode_hash(h) for h in second.consistency_proof(old_size)]
        assert merkle.verify_consistency(
            old_size, second.tree_size, old_root, second.root(), proof
        )


class TestAppendOnlyIsEnforcedBySchema:
    def test_a_second_write_at_the_same_index_is_refused(self, tmp_path):
        storage = SqliteLogStorage(tmp_path / "log.sqlite3")
        storage.append(0, b"first", merkle.leaf_hash(b"first"))
        with pytest.raises(sqlite3.IntegrityError):
            storage.append(0, b"second", merkle.leaf_hash(b"second"))

    def test_the_in_memory_tree_does_not_advance_past_a_failed_write(self, tmp_path, log_key):
        """A log that counts an entry it failed to persist would shrink on restart."""
        log = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(tmp_path / "log.sqlite3"))
        log.append(document(0))
        log.storage.close()  # every later write now raises

        with pytest.raises(sqlite3.ProgrammingError):
            log.append(document(1))
        assert log.tree_size == 1


class TestCorruptionIsDetectedAndTamperingIsNot:
    def test_an_entry_that_no_longer_hashes_to_its_leaf_is_refused(self, tmp_path, log_key):
        path = tmp_path / "log.sqlite3"
        log = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        log.append(document(0))
        log.storage.close()

        connection = sqlite3.connect(path)
        with connection:
            connection.execute("UPDATE log_entries SET entry = ? WHERE idx = 0", (b"tampered",))
        connection.close()

        with pytest.raises(LogCorrupted):
            TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))

    def test_a_rewritten_row_with_a_matching_leaf_loads_cleanly(self, tmp_path, log_key):
        """Documents the limit rather than papering over it.

        Whoever can write this database can rewrite an entry and its leaf together, and
        the storage layer cannot tell. That is why tamper-evidence lives with the witness
        in another trust domain and not here -- the root the witness already accepted no
        longer matches, and it is the party that notices.
        """
        path = tmp_path / "log.sqlite3"
        log = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        log.append(document(0))
        original_root = log.root()
        log.storage.close()

        forged = b'{"forged":true}'
        connection = sqlite3.connect(path)
        with connection:
            connection.execute(
                "UPDATE log_entries SET entry = ?, leaf = ? WHERE idx = 0",
                (forged, merkle.leaf_hash(forged)),
            )
        connection.close()

        reopened = TransparencyLog(LOG_ID, log_key, storage=SqliteLogStorage(path))
        assert reopened.tree_size == 1  # storage saw nothing wrong
        assert reopened.root() != original_root  # the root is what gives it away
