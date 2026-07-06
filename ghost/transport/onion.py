"""
ghost.transport.onion — Simulated onion routing layer for SpectrumQ.

Provides layered AES-256-GCM encryption across N relay hops, where each hop
knows only its predecessor and successor (not origin or destination).

Wire format per layer
---------------------
struct OnionLayer {
  version:    u8      = 1
  circuit_id: bytes[16]   (UUID as bytes)
  hop_index:  u8
  nonce:      bytes[12]
  ciphertext: bytes[...]  (AES-GCM encrypted payload + 16-byte tag)
}
Serialized as: version(1) + circuit_id(16) + hop_index(1) + nonce(12) + ciphertext

Usage
-----
    router = OnionRouter()
    relay_pool = [RelayNode() for _ in range(5)]
    circuit = router.build_circuit(relay_pool, hops=3)
    onion = router.wrap(circuit, b"secret message")
    plaintext = router.unwrap_all(circuit, onion)
    assert plaintext == b"secret message"
"""

from __future__ import annotations

import os
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from ghost.crypto.keys import EphemeralKey


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LAYER_VERSION: int = 1
_HEADER_SIZE: int = 1 + 16 + 1 + 12  # version + circuit_id + hop_index + nonce = 30
_NONCE_LEN: int = 12
_KEY_LEN: int = 32
_TAG_LEN: int = 16


# ---------------------------------------------------------------------------
# RelayNode
# ---------------------------------------------------------------------------


class RelayNode:
    """
    Simulated relay node in the onion network.

    Each relay node holds an ephemeral X25519 key pair and can peel one
    layer of onion encryption during circuit simulation.

    Attributes
    ----------
    node_id : str
        Unique identifier for this relay node.
    ephemeral_key : EphemeralKey
        X25519 ephemeral key pair for ECDH key agreement.
    """

    def __init__(self, node_id: Optional[str] = None) -> None:
        """
        Initialize a relay node with a unique ID and fresh ephemeral key.

        Parameters
        ----------
        node_id : str, optional
            Custom node identifier. Defaults to a new UUID4 string.
        """
        self.node_id: str = node_id if node_id is not None else str(uuid.uuid4())
        self.ephemeral_key: EphemeralKey = EphemeralKey()

    def __repr__(self) -> str:  # pragma: no cover
        return f"RelayNode(node_id={self.node_id!r})"


# ---------------------------------------------------------------------------
# OnionCircuit
# ---------------------------------------------------------------------------


@dataclass
class OnionCircuit:
    """
    Represents an active onion routing circuit.

    A circuit encapsulates the ordered list of relay hops and the per-hop
    symmetric keys derived from X25519 ECDH with each relay node.

    Attributes
    ----------
    circuit_id : str
        UUID4 string uniquely identifying this circuit.
    hops : list of RelayNode
        Ordered relay nodes; hops[0] is the entry node, hops[-1] is the exit.
    layers : list of (bytes, int)
        Per-hop (symmetric_key_32_bytes, nonce_counter) tuples, outermost first
        (i.e., layers[0] corresponds to hops[0], the entry node).
    max_messages : int
        Maximum number of messages before the circuit expires (default 100).
    created_at : float
        Unix timestamp when this circuit was created.
    message_count : int
        Number of messages wrapped through this circuit so far.
    expired : bool
        True once the circuit has been explicitly torn down or max_messages hit.
    """

    circuit_id: str
    hops: List[RelayNode]
    layers: List[Tuple[bytes, int]]  # (symmetric_key, nonce_counter)
    max_messages: int = 100
    created_at: float = field(default_factory=time.time)
    message_count: int = 0
    expired: bool = False

    @property
    def circuit_id_bytes(self) -> bytes:
        """Return circuit_id as 16 raw bytes (UUID bytes)."""
        return uuid.UUID(self.circuit_id).bytes

    def is_expired(self) -> bool:
        """Return True if the circuit is expired (by count or explicit teardown)."""
        return self.expired or self.message_count >= self.max_messages

    def _check_not_expired(self) -> None:
        """Raise ValueError if the circuit is expired."""
        if self.is_expired():
            raise ValueError(
                f"Circuit {self.circuit_id} is expired "
                f"(messages={self.message_count}, max={self.max_messages}, "
                f"expired={self.expired})"
            )


# ---------------------------------------------------------------------------
# OnionRouter
# ---------------------------------------------------------------------------


class OnionRouter:
    """
    Manages onion circuits: building, wrapping, unwrapping, and teardown.

    The router maintains a registry of active circuits keyed by circuit_id.
    In simulation mode, it holds all relay keys locally so that tests can
    verify end-to-end unwrapping without a real network.
    """

    def __init__(self) -> None:
        """Initialize an empty OnionRouter."""
        self._circuits: Dict[str, OnionCircuit] = {}

    # ------------------------------------------------------------------
    # Circuit building
    # ------------------------------------------------------------------

    def build_circuit(
        self,
        relay_pool: List[RelayNode],
        hops: int = 3,
    ) -> OnionCircuit:
        """
        Select *hops* relay nodes from *relay_pool* and build a new circuit.

        For each selected relay node a fresh X25519 ECDH exchange is performed
        between an ephemeral router key and the relay's public key.  The
        resulting shared secret is run through HKDF-SHA256 to derive a 32-byte
        AES-256 key for that layer.

        Parameters
        ----------
        relay_pool : list of RelayNode
            Pool from which relay nodes are randomly selected (without replacement).
        hops : int
            Number of hops (relay nodes) in the circuit.  Must be ≥ 1 and
            ≤ len(relay_pool).

        Returns
        -------
        OnionCircuit
            Registered circuit ready for use with :meth:`wrap`.

        Raises
        ------
        ValueError
            If *hops* < 1 or *hops* > len(relay_pool).
        """
        if hops < 1:
            raise ValueError(f"hops must be >= 1, got {hops}")
        if hops > len(relay_pool):
            raise ValueError(
                f"Not enough relay nodes: requested {hops} hops "
                f"but pool has only {len(relay_pool)} nodes"
            )

        # Select hops random relay nodes (without replacement)
        indices = list(range(len(relay_pool)))
        selected_indices: List[int] = []
        pool_copy = indices[:]
        for _ in range(hops):
            idx = int.from_bytes(os.urandom(4), "big") % len(pool_copy)
            selected_indices.append(pool_copy.pop(idx))
        selected_nodes = [relay_pool[i] for i in selected_indices]

        # Derive per-hop symmetric keys via X25519 ECDH + HKDF
        circuit_id = str(uuid.uuid4())
        circuit_id_bytes = uuid.UUID(circuit_id).bytes
        layers: List[Tuple[bytes, int]] = []

        for hop_index, node in enumerate(selected_nodes):
            # Generate ephemeral router key for this hop
            router_ephemeral = EphemeralKey()

            # X25519 ECDH: router_ephemeral_private × relay_public
            relay_public = node.ephemeral_key._private_key.public_key()
            shared_secret = router_ephemeral._private_key.exchange(relay_public)

            # HKDF-SHA256 to derive 32-byte AES key
            info = b"ghost-onion-v1" + circuit_id_bytes + hop_index.to_bytes(1, "big")
            symmetric_key = HKDF(
                algorithm=SHA256(),
                length=_KEY_LEN,
                salt=None,
                info=info,
                backend=default_backend(),
            ).derive(shared_secret)

            # Also store the router ephemeral key so relay can reproduce ECDH
            # (needed for simulation: relay must derive the same shared secret)
            layers.append((symmetric_key, 0))
            # Attach the router_ephemeral to the node for simulation purposes
            node._router_ephemeral = router_ephemeral  # type: ignore[attr-defined]

        circuit = OnionCircuit(
            circuit_id=circuit_id,
            hops=selected_nodes,
            layers=layers,
        )
        self._circuits[circuit_id] = circuit
        return circuit

    # ------------------------------------------------------------------
    # Wrapping (encryption)
    # ------------------------------------------------------------------

    def wrap(self, circuit: OnionCircuit, plaintext: bytes) -> bytes:
        """
        Wrap *plaintext* in N layers of AES-256-GCM encryption.

        Encryption is applied innermost-first (exit hop → entry hop), so the
        outermost layer can be peeled by the entry (first) relay node.

        Each layer's associated data is: circuit_id_bytes + hop_index_byte,
        binding the ciphertext to both the circuit and the specific hop position.

        Parameters
        ----------
        circuit : OnionCircuit
            The circuit to use for wrapping.
        plaintext : bytes
            The cleartext message to encrypt.

        Returns
        -------
        bytes
            The fully-wrapped onion ciphertext (outermost layer first).

        Raises
        ------
        ValueError
            If the circuit is expired.
        """
        circuit._check_not_expired()

        data = plaintext
        # Apply layers from innermost (last hop) to outermost (first hop)
        for hop_index in range(len(circuit.hops) - 1, -1, -1):
            sym_key, nonce_counter = circuit.layers[hop_index]
            nonce = os.urandom(_NONCE_LEN)
            associated_data = circuit.circuit_id_bytes + hop_index.to_bytes(1, "big")
            aesgcm = AESGCM(sym_key)
            ciphertext = aesgcm.encrypt(nonce, data, associated_data)
            # Serialize layer header + ciphertext
            header = (
                bytes([_LAYER_VERSION])
                + circuit.circuit_id_bytes
                + hop_index.to_bytes(1, "big")
                + nonce
            )
            data = header + ciphertext
            # Increment nonce counter
            circuit.layers[hop_index] = (sym_key, nonce_counter + 1)

        circuit.message_count += 1
        return data

    # ------------------------------------------------------------------
    # Unwrapping (decryption)
    # ------------------------------------------------------------------

    def unwrap_one(self, relay_node: RelayNode, onion_ct: bytes) -> bytes:
        """
        Peel one layer of the onion, as a relay node would.

        This simulates a relay node receiving an onion packet and decrypting
        its outermost layer using the symmetric key it shares with the circuit
        builder.  The relay does NOT learn the origin or final destination.

        Parameters
        ----------
        relay_node : RelayNode
            The relay node peeling the outermost layer.  Must have a
            ``_router_ephemeral`` attribute set by :meth:`build_circuit`
            (simulation only).
        onion_ct : bytes
            The onion ciphertext to peel.

        Returns
        -------
        bytes
            The inner ciphertext after removing one layer.

        Raises
        ------
        ValueError
            If the header is malformed, the version is unknown, the relay
            does not hold a key for this circuit, or AEAD authentication fails.
        """
        if len(onion_ct) < _HEADER_SIZE:
            raise ValueError(
                f"Onion ciphertext too short: {len(onion_ct)} < {_HEADER_SIZE}"
            )

        version = onion_ct[0]
        if version != _LAYER_VERSION:
            raise ValueError(f"Unknown onion version: {version}")

        circuit_id_bytes = onion_ct[1:17]
        hop_index = onion_ct[17]
        nonce = onion_ct[18:30]
        ciphertext = onion_ct[30:]

        circuit_id_str = str(uuid.UUID(bytes=circuit_id_bytes))

        # Look up circuit
        circuit = self._circuits.get(circuit_id_str)
        if circuit is None:
            raise ValueError(f"Unknown circuit: {circuit_id_str}")

        if hop_index >= len(circuit.hops):
            raise ValueError(
                f"hop_index {hop_index} out of range for circuit with "
                f"{len(circuit.hops)} hops"
            )

        # Verify this relay is the expected hop
        expected_node = circuit.hops[hop_index]
        if expected_node.node_id != relay_node.node_id:
            raise ValueError(
                f"relay_node {relay_node.node_id!r} is not the expected hop "
                f"{hop_index} node {expected_node.node_id!r}"
            )

        sym_key = circuit.layers[hop_index][0]
        associated_data = circuit_id_bytes + hop_index.to_bytes(1, "big")
        aesgcm = AESGCM(sym_key)

        try:
            inner = aesgcm.decrypt(nonce, ciphertext, associated_data)
        except Exception as exc:
            raise ValueError(f"AEAD authentication failed at hop {hop_index}: {exc}") from exc

        return inner

    def unwrap_all(self, circuit: OnionCircuit, onion_ct: bytes) -> bytes:
        """
        Fully unwrap an onion ciphertext using all circuit layers.

        Applies each layer from outermost (hop 0) to innermost (hop N-1),
        recovering the original plaintext.  Used in tests and for end-to-end
        verification without simulating individual relay hops.

        Parameters
        ----------
        circuit : OnionCircuit
            The circuit whose keys are used for decryption.
        onion_ct : bytes
            The fully-wrapped onion ciphertext.

        Returns
        -------
        bytes
            The recovered plaintext.

        Raises
        ------
        ValueError
            If any layer fails to decrypt (tampered ciphertext, wrong circuit, etc.).
        """
        data = onion_ct
        for hop_index in range(len(circuit.hops)):
            if len(data) < _HEADER_SIZE:
                raise ValueError(
                    f"Truncated onion at hop {hop_index}: "
                    f"{len(data)} < {_HEADER_SIZE}"
                )

            version = data[0]
            if version != _LAYER_VERSION:
                raise ValueError(f"Unknown onion version: {version}")

            circuit_id_bytes = data[1:17]
            layer_hop_index = data[17]
            nonce = data[18:30]
            ciphertext = data[30:]

            if layer_hop_index != hop_index:
                raise ValueError(
                    f"Expected hop_index {hop_index}, got {layer_hop_index}"
                )

            sym_key = circuit.layers[hop_index][0]
            associated_data = circuit_id_bytes + hop_index.to_bytes(1, "big")
            aesgcm = AESGCM(sym_key)

            try:
                data = aesgcm.decrypt(nonce, ciphertext, associated_data)
            except Exception as exc:
                raise ValueError(
                    f"AEAD authentication failed at hop {hop_index}: {exc}"
                ) from exc

        return data

    # ------------------------------------------------------------------
    # Circuit teardown
    # ------------------------------------------------------------------

    def expire_circuit(self, circuit_id: str) -> None:
        """
        Explicitly expire and remove a circuit.

        After calling this, any attempt to :meth:`wrap` with the circuit
        will raise :class:`ValueError`.

        Parameters
        ----------
        circuit_id : str
            The circuit ID to expire and remove from the registry.

        Raises
        ------
        ValueError
            If *circuit_id* is not found in the active circuit registry.
        """
        circuit = self._circuits.get(circuit_id)
        if circuit is None:
            raise ValueError(f"Circuit not found: {circuit_id}")
        circuit.expired = True
        del self._circuits[circuit_id]
