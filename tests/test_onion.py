"""
tests/test_onion.py — Test suite for ghost.transport.onion (GHOST v0.4).

Tests
-----
TestOnionCircuit   — Circuit lifecycle, wrap/unwrap, expiry
TestOnionLayers    — Layer counts, sizes, and tamper detection
TestRelaySimulation — Per-hop relay peeling simulation
"""

from __future__ import annotations

import struct
import time
import uuid
from typing import List

import pytest

from ghost.transport.onion import (
    OnionCircuit,
    OnionRouter,
    RelayNode,
    _HEADER_SIZE,
    _LAYER_VERSION,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_relay_pool(n: int = 10) -> List[RelayNode]:
    """Return a list of *n* fresh RelayNode instances."""
    return [RelayNode() for _ in range(n)]


def make_circuit(hops: int = 3, pool_size: int = 10) -> tuple:
    """Return (router, relay_pool, circuit)."""
    router = OnionRouter()
    pool = make_relay_pool(pool_size)
    circuit = router.build_circuit(pool, hops=hops)
    return router, pool, circuit


# ---------------------------------------------------------------------------
# TestOnionCircuit
# ---------------------------------------------------------------------------


class TestOnionCircuit:
    """Tests for circuit lifecycle, wrap/unwrap, and expiry."""

    def test_build_circuit_selects_n_hops(self):
        """build_circuit should select exactly *hops* relay nodes."""
        router = OnionRouter()
        pool = make_relay_pool(10)
        for n in (1, 2, 3, 5, 7):
            circuit = router.build_circuit(pool, hops=n)
            assert len(circuit.hops) == n, f"Expected {n} hops, got {len(circuit.hops)}"

    def test_circuit_has_unique_id(self):
        """Each circuit should have a unique UUID4 circuit_id."""
        router = OnionRouter()
        pool = make_relay_pool(10)
        ids = {router.build_circuit(pool, hops=3).circuit_id for _ in range(20)}
        assert len(ids) == 20, "Circuit IDs should all be unique"
        # Each ID must be a valid UUID
        for cid in ids:
            parsed = uuid.UUID(cid)
            assert parsed.version == 4

    def test_wrap_returns_bytes(self):
        """wrap() should return a bytes object."""
        router, pool, circuit = make_circuit(3)
        result = router.wrap(circuit, b"hello world")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_unwrap_all_recovers_plaintext(self):
        """unwrap_all(wrap(plaintext)) should equal plaintext."""
        router, pool, circuit = make_circuit(3)
        plaintext = b"the quick brown fox"
        onion = router.wrap(circuit, plaintext)
        recovered = router.unwrap_all(circuit, onion)
        assert recovered == plaintext

    def test_each_hop_sees_different_ciphertext(self):
        """
        The ciphertext visible at each hop should be different from
        adjacent layers (no layer is a subset of the next in plaintext).
        """
        router, pool, circuit = make_circuit(3)
        plaintext = b"multi-layer secret"
        onion = router.wrap(circuit, plaintext)

        # Peel layers one by one and collect the ciphertext seen at each hop
        ciphertexts = [onion]
        data = onion
        for hop_index in range(len(circuit.hops)):
            # Decrypt one layer
            nonce = data[18:30]
            ct = data[30:]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            sym_key = circuit.layers[hop_index][0]
            ad = circuit.circuit_id_bytes + hop_index.to_bytes(1, "big")
            inner = AESGCM(sym_key).decrypt(nonce, ct, ad)
            if hop_index < len(circuit.hops) - 1:
                ciphertexts.append(inner)
            data = inner

        # All collected byte strings should be distinct
        for i in range(len(ciphertexts)):
            for j in range(i + 1, len(ciphertexts)):
                assert ciphertexts[i] != ciphertexts[j], (
                    f"Layer {i} and layer {j} ciphertexts are identical"
                )

    def test_circuit_expires_after_max_messages(self):
        """After max_messages wraps, is_expired() should return True."""
        router, pool, circuit = make_circuit(2)
        circuit.max_messages = 5
        plaintext = b"x"
        for _ in range(5):
            assert not circuit.is_expired()
            router.wrap(circuit, plaintext)
        assert circuit.is_expired()

    def test_expired_circuit_raises_on_wrap(self):
        """wrap() on an expired circuit should raise ValueError."""
        router, pool, circuit = make_circuit(2)
        circuit.max_messages = 3
        for _ in range(3):
            router.wrap(circuit, b"msg")
        with pytest.raises(ValueError, match="expired"):
            router.wrap(circuit, b"too late")


# ---------------------------------------------------------------------------
# TestOnionLayers
# ---------------------------------------------------------------------------


class TestOnionLayers:
    """Tests for layer structure, sizing, and tamper detection."""

    def test_single_hop_circuit(self):
        """A 1-hop circuit should wrap/unwrap correctly."""
        router, pool, circuit = make_circuit(hops=1)
        plaintext = b"single hop test"
        onion = router.wrap(circuit, plaintext)
        recovered = router.unwrap_all(circuit, onion)
        assert recovered == plaintext

    def test_three_hop_circuit(self):
        """A 3-hop circuit should wrap/unwrap correctly."""
        router, pool, circuit = make_circuit(hops=3)
        plaintext = b"three hop test"
        onion = router.wrap(circuit, plaintext)
        recovered = router.unwrap_all(circuit, onion)
        assert recovered == plaintext

    def test_five_hop_circuit(self):
        """A 5-hop circuit should wrap/unwrap correctly."""
        router, pool, circuit = make_circuit(hops=5)
        plaintext = b"five hop test"
        onion = router.wrap(circuit, plaintext)
        recovered = router.unwrap_all(circuit, onion)
        assert recovered == plaintext

    def test_layer_sizes_grow_with_hops(self):
        """
        More hops → larger onion packet.

        Each additional hop adds at least _HEADER_SIZE + _TAG_LEN bytes.
        """
        plaintext = b"size test payload"
        pool = make_relay_pool(10)

        prev_size = None
        for n in (1, 2, 3, 4, 5):
            router = OnionRouter()
            circuit = router.build_circuit(pool, hops=n)
            onion = router.wrap(circuit, plaintext)
            if prev_size is not None:
                assert len(onion) > prev_size, (
                    f"Onion with {n} hops ({len(onion)}) should be larger "
                    f"than {n-1} hops ({prev_size})"
                )
            prev_size = len(onion)

    def test_tampered_outer_layer_raises(self):
        """Flipping a byte in the outer ciphertext should cause decryption failure."""
        router, pool, circuit = make_circuit(3)
        onion = router.wrap(circuit, b"tamper test")
        # Flip a byte in the ciphertext area (after the 30-byte header)
        tampered = bytearray(onion)
        tampered[_HEADER_SIZE] ^= 0xFF
        with pytest.raises(ValueError):
            router.unwrap_all(circuit, bytes(tampered))

    def test_associated_data_bound_to_circuit(self):
        """
        Copying a layer from one circuit into another should fail AEAD
        authentication because the associated data (circuit_id) differs.
        """
        pool = make_relay_pool(10)
        router = OnionRouter()
        circuit_a = router.build_circuit(pool[:5], hops=3)
        circuit_b = router.build_circuit(pool[5:], hops=3)

        onion_a = router.wrap(circuit_a, b"circuit A message")

        # Try to decrypt circuit_a's onion using circuit_b's keys
        # (different circuit_id → different associated data → AEAD fail)
        with pytest.raises(ValueError):
            router.unwrap_all(circuit_b, onion_a)


# ---------------------------------------------------------------------------
# TestRelaySimulation
# ---------------------------------------------------------------------------


class TestRelaySimulation:
    """Tests that simulate per-hop relay peeling."""

    def test_relay_peels_one_layer(self):
        """
        unwrap_one on the entry relay should produce the inner ciphertext
        (which differs from the original onion packet).
        """
        router, pool, circuit = make_circuit(3)
        plaintext = b"relay peel test"
        onion = router.wrap(circuit, plaintext)

        entry_relay = circuit.hops[0]
        inner = router.unwrap_one(entry_relay, onion)

        assert isinstance(inner, bytes)
        assert inner != onion
        assert len(inner) < len(onion)

    def test_sequential_relay_unwrap_matches_direct(self):
        """
        Peeling hop-by-hop through each relay node should yield the same
        plaintext as calling unwrap_all directly.
        """
        router, pool, circuit = make_circuit(3)
        plaintext = b"sequential relay test"
        onion = router.wrap(circuit, plaintext)

        # Simulate each relay peeling its layer
        data = onion
        for hop_index, relay in enumerate(circuit.hops):
            if hop_index < len(circuit.hops) - 1:
                data = router.unwrap_one(relay, data)
            else:
                # Last hop: unwrap_one gives the plaintext
                data = router.unwrap_one(relay, data)

        assert data == plaintext

    def test_relay_cannot_see_inner_plaintext(self):
        """
        The data returned by unwrap_one for the entry relay is still
        encrypted (it contains another onion layer header, not plaintext).
        """
        router, pool, circuit = make_circuit(3)
        plaintext = b"relay cannot read this"
        onion = router.wrap(circuit, plaintext)

        # Entry relay peels one layer
        entry_relay = circuit.hops[0]
        after_hop0 = router.unwrap_one(entry_relay, onion)

        # after_hop0 should NOT be plaintext (it still has layers)
        assert after_hop0 != plaintext

        # It should still be a valid onion layer (starts with version byte)
        if len(circuit.hops) > 1:
            assert after_hop0[0] == _LAYER_VERSION
            # The hop_index in the next layer should be 1
            assert after_hop0[17] == 1
