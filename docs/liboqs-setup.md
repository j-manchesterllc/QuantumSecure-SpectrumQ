# liboqs Setup Guide

SpectrumQ uses **ML-KEM-768** (FIPS 203) for post-quantum key encapsulation. ML-KEM-768 is provided by [liboqs](https://github.com/open-quantum-safe/liboqs) — the Open Quantum Safe project's C library — accessed via Python bindings (`liboqs-python`).

Without liboqs, SpectrumQ automatically falls back to an X25519-based classical KEM. The fallback exposes the same API and provides strong classical security, but is **not post-quantum resistant**. Install liboqs for full SpectrumQ security guarantees.

---

## Prerequisites

Install build dependencies before compiling liboqs:

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    libssl-dev \
    python3-dev \
    git
```

### macOS (Homebrew)

```bash
brew install cmake ninja openssl
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install -y \
    gcc gcc-c++ make \
    cmake \
    ninja-build \
    openssl-devel \
    python3-devel \
    git
```

---

## Build liboqs from Source

SpectrumQ is tested against **liboqs 0.10.x**. The exact cmake flags below match what this project uses.

```bash
# 1. Clone the repository
git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# 2. Configure (enable only the algorithms SpectrumQ needs)
cmake -B build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_ENABLE_KEM_ML_KEM=ON \
    -DOQS_ENABLE_KEM_kyber=OFF \
    -DOQS_ENABLE_SIG_dilithium=OFF \
    -DOQS_ENABLE_SIG_falcon=OFF \
    -DCMAKE_INSTALL_PREFIX=/usr/local

# 3. Build
cmake --build build --parallel $(nproc)

# 4. Install (writes to /usr/local/lib and /usr/local/include)
sudo cmake --install build
```

> **Tip:** If you don't want a system-wide install, set `-DCMAKE_INSTALL_PREFIX=$HOME/.local` and adjust paths below accordingly.

---

## Set LD_LIBRARY_PATH

The liboqs shared library must be findable at runtime. After installing:

```bash
# For a system install (/usr/local/lib):
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# For a custom prefix (e.g. $HOME/.local/lib):
export LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH

# Make it permanent — add to ~/.bashrc or ~/.zshrc:
echo 'export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH' >> ~/.bashrc
```

On macOS, use `DYLD_LIBRARY_PATH` instead of `LD_LIBRARY_PATH`.

---

## Install Python Bindings

```bash
# Install liboqs-python (wraps the C library)
pip install liboqs-python>=0.10

# Or install SpectrumQ with the pq extra (includes liboqs-python):
pip install "ghost-spectrumq[pq]"
```

> `liboqs-python` is a thin CFFI wrapper — it does **not** bundle the C library. liboqs must be installed separately (steps above) before `liboqs-python` will work.

---

## Verify the Installation

Run the built-in KEM check:

```bash
python - <<'EOF'
try:
    import oqs
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pk, sk = kem.generate_keypair()
    ct, ss_enc = kem.encap_secret(pk)
    ss_dec = kem.decap_secret(ct)
    assert ss_enc == ss_dec
    print("✅ ML-KEM-768 available and working")
except ImportError:
    print("❌ liboqs-python not found — X25519 fallback will be used")
except Exception as e:
    print(f"❌ liboqs error: {e}")
EOF
```

Or run SpectrumQ's own KEM tests:

```bash
export LD_LIBRARY_PATH=/usr/local/lib
python -m pytest tests/test_kem.py -v
```

---

## Confirming PQ Mode in SpectrumQ

When SpectrumQ starts with liboqs available, the KEM module logs:

```
[ghost.crypto.kem] ML-KEM-768 available via liboqs — post-quantum mode active
```

Without liboqs:

```
[ghost.crypto.kem] liboqs not available — falling back to X25519 pseudo-KEM (classical only)
```

You can also check programmatically:

```python
from ghost.crypto.kem import MLKEM_AVAILABLE
print("Post-quantum:", MLKEM_AVAILABLE)
```

---

## Troubleshooting

**`OSError: liboqs.so.x not found`**
The shared library is not on the linker path. Set `LD_LIBRARY_PATH` as shown above, or run `sudo ldconfig` after a system install.

**`cmake: command not found`**
Install cmake via your package manager (see Prerequisites above).

**Build fails on `OQS_ENABLE_KEM_ML_KEM`**
Older liboqs versions (< 0.10) use `OQS_ENABLE_KEM_KYBER` instead of the ML-KEM naming. Use liboqs 0.10.x or later, which implements the final FIPS 203 ML-KEM standard.

**`liboqs-python` version mismatch**
`liboqs-python` must match the installed liboqs C library version. Both should be 0.10.x. Mismatched versions will cause import errors or segfaults.

---

## References

- [liboqs GitHub](https://github.com/open-quantum-safe/liboqs)
- [liboqs-python GitHub](https://github.com/open-quantum-safe/liboqs-python)
- [FIPS 203 — ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
