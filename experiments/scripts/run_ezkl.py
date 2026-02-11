"""
EzKL proof for regex-based PII filter: build ONNX from regex logic, then prove/verify.

- Export regex PII logic to a small ONNX (input [1, 128] bytes -> output: PII count).
- Setup: gen_settings, compile, get_srs, setup.
- Prove: encode text -> witness -> proof (bound to hash of output).
- Verify: check proof with vk/settings/srs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


def _set_ezkl_env(proofs_dir: Path) -> None:
    """Set env vars ezkl expects on Windows to avoid NotPresent / path panics (see zkonduit/ezkl issues)."""
    proofs_dir = Path(proofs_dir).resolve()
    ezkl_home = proofs_dir / ".ezkl"
    ezkl_home.mkdir(parents=True, exist_ok=True)
    if "EZKL_REPO_PATH" not in os.environ:
        os.environ["EZKL_REPO_PATH"] = str(ezkl_home)
    if "EZKL_WORKING_DIR" not in os.environ:
        os.environ["EZKL_WORKING_DIR"] = str(proofs_dir)
    # On Windows, ezkl lazy_static may use HOME; set if missing so default EZKL_REPO_PATH doesn't panic
    if os.name == "nt" and "HOME" not in os.environ:
        os.environ["HOME"] = str(proofs_dir)

EXPERIMENTS_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MODELS_DIR = EXPERIMENTS_DIR / "models"
DEFAULT_PROOFS_DIR = EXPERIMENTS_DIR / "proofs"
REGEX_PII_ONNX = DEFAULT_MODELS_DIR / "regex_pii.onnx"
# Official EzKL example; use with --onnx to test if setup works (isolates NotPresent to our ONNX or ezkl)
EXAMPLE_1L_LINEAR_ONNX = DEFAULT_MODELS_DIR / "ezkl_example_1l_linear" / "network.onnx"
MAX_LEN = 128


# ---------------------------------------------------------------------------
# Regex PII -> ONNX
# ---------------------------------------------------------------------------


def export_regex_pii_onnx(onnx_path: str | Path) -> Path:
    """
    Build a minimal ONNX that encodes regex-PII detection: input [1, 128] float (bytes/255),
    output [1, 1] = count of 'suspicious' bytes (e.g. @ for email). Pass = output 0.
    """
    import torch
    import torch.nn as nn

    class RegexPIIModule(nn.Module):
        # Detect bytes that often appear in PII: @ (64), digits 0-9 (48-57), - (45), . (46)
        SUSPICIOUS = (64, 45, 46) + tuple(range(48, 58))

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            # x: [1, 128], values in [0, 1] (byte/255)
            out = torch.zeros(x.shape[0], 1, dtype=x.dtype, device=x.device)
            for b in self.SUSPICIOUS:
                out = out + (x == (b / 255.0)).to(x.dtype).sum(dim=1, keepdim=True)
            return out

    model = RegexPIIModule()
    model.eval()
    dummy = torch.rand(1, MAX_LEN)
    onnx_path = Path(onnx_path)
    onnx_path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model,
        dummy,
        str(onnx_path),
        input_names=["input"],
        output_names=["output"],
        opset_version=14,
    )
    return onnx_path


# ---------------------------------------------------------------------------
# Encode text for circuit
# ---------------------------------------------------------------------------


def encode_output_for_circuit(text: str, max_len: int = MAX_LEN) -> list[list[float]]:
    """Encode text as [1, max_len] floats (UTF-8 bytes / 255)."""
    raw = text.encode("utf-8")
    row = [raw[i] / 255.0 if i < len(raw) else 0.0 for i in range(max_len)]
    return [row]


def compute_output_hash_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class GenerateProofResult:
    success: bool
    proof_path: str | None = None
    vk_path: str | None = None
    output_hash_sha256_hex: str = ""
    timings_ms: dict[str, float] = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# EzKL: setup, prove, verify
# ---------------------------------------------------------------------------


def _ensure_ezkl():
    try:
        import ezkl  # noqa: F401
    except ImportError as e:
        raise ImportError("pip install ezkl") from e


def _check_file(path: Path, must_be_json: bool = False, min_size: int = 1) -> None:
    """Raise if path missing, empty, or (if must_be_json) invalid JSON. Avoids ezkl panics like 'expected value, line: 1, column: 1'."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Missing file: {path}")
    if path.stat().st_size < min_size:
        raise ValueError(f"File empty or too small: {path} (size {path.stat().st_size})")
    if must_be_json:
        with open(path) as f:
            data = json.load(f)
        if data is None or (isinstance(data, (list, dict)) and len(data) == 0):
            raise ValueError(f"JSON file has no content: {path}")


def setup_artifacts(
    onnx_path: str | Path,
    models_dir: Path | str | None = None,
    proofs_dir: Path | str | None = None,
) -> dict[str, str]:
    """Gen settings, compile circuit, get SRS, setup. Returns paths."""
    onnx_path = Path(onnx_path)
    if not onnx_path.is_file():
        raise FileNotFoundError(onnx_path)
    models = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
    proofs = Path(proofs_dir) if proofs_dir else DEFAULT_PROOFS_DIR
    models.mkdir(parents=True, exist_ok=True)
    proofs.mkdir(parents=True, exist_ok=True)
    _set_ezkl_env(proofs)
    _ensure_ezkl()
    import ezkl

    settings_path = models / "settings.json"
    compiled_path = models / "compiled.ezkl"
    srs_path = proofs / "kzg.srs"
    vk_path = proofs / "vk.key"
    pk_path = proofs / "pk.key"

    run_args = ezkl.PyRunArgs()
    run_args.input_visibility = "hashed/public"
    run_args.output_visibility = "public"
    run_args.param_visibility = "fixed"

    ezkl.gen_settings(str(onnx_path), str(settings_path), run_args)
    ezkl.compile_circuit(str(onnx_path), str(compiled_path), str(settings_path))

    # Run get_srs + SRS wait + gen_witness + setup inside one event loop (sync calls, no await).
    # Keeps the loop active for the whole chain; can avoid "NotPresent" on Windows in some EzKL builds.
    import asyncio

    async def _run_setup_with_loop() -> None:
        ezkl.get_srs(str(settings_path), srs_path=str(srs_path))
        srs_file = Path(srs_path)
        for _ in range(30):
            if srs_file.is_file() and srs_file.stat().st_size > 1_000_000:
                break
            await asyncio.sleep(2)
        if not srs_file.is_file() or srs_file.stat().st_size == 0:
            logger.warning("SRS missing or empty; generating locally (gen_srs, testing only)")
            with open(settings_path) as f:
                logrows = int(json.load(f).get("run_args", {}).get("logrows", 17))
            ezkl.gen_srs(str(srs_path), logrows)
        elif srs_file.stat().st_size < 1_000_000:
            logger.warning("SRS file too small; generating locally (gen_srs).")
            with open(settings_path) as f:
                logrows = int(json.load(f).get("run_args", {}).get("logrows", 17))
            ezkl.gen_srs(str(srs_path), logrows)
        # Ensure files ezkl will read are non-empty valid JSON / exist (avoids "expected value, line 1, column 1" panics)
        _check_file(settings_path, must_be_json=True)
        _check_file(compiled_path, min_size=100)
        _check_file(srs_path, min_size=1)  # SRS may be small if from gen_srs
        dummy_data = proofs / "input.json"
        # Use example input shape for 1l_linear; otherwise our regex [1,128] float input
        use_1l_linear = EXAMPLE_1L_LINEAR_ONNX.resolve() == onnx_path.resolve()
        if use_1l_linear:
            input_payload = [[0.0]]  # 1l_linear expects single scalar
        else:
            input_payload = encode_output_for_circuit("")
        with open(dummy_data, "w") as f:
            json.dump({"input_data": input_payload}, f)
            f.flush()
        _check_file(dummy_data, must_be_json=True)
        setup_witness = proofs / "setup_witness.json"
        ezkl.gen_witness(str(dummy_data), str(compiled_path), str(setup_witness), srs_path=str(srs_path))
        ezkl.setup(str(compiled_path), str(vk_path), str(pk_path), srs_path=str(srs_path))

    asyncio.run(_run_setup_with_loop())

    return {
        "settings_path": str(settings_path),
        "compiled_path": str(compiled_path),
        "srs_path": str(srs_path),
        "vk_path": str(vk_path),
        "pk_path": str(pk_path),
    }


def generate_proof(
    output_text: str,
    onnx_path: str | Path | None = None,
    models_dir: Path | str | None = None,
    proofs_dir: Path | str | None = None,
    proof_filename: str = "proof.json",
) -> GenerateProofResult:
    """Encode output, gen witness, prove. Runs setup if keys missing."""
    onnx_path = Path(onnx_path) if onnx_path else REGEX_PII_ONNX
    models = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
    proofs = Path(proofs_dir) if proofs_dir else DEFAULT_PROOFS_DIR
    proofs.mkdir(parents=True, exist_ok=True)
    _set_ezkl_env(proofs)
    _ensure_ezkl()
    import ezkl

    compiled_path = models / "compiled.ezkl"
    srs_path = proofs / "kzg.srs"
    pk_path = proofs / "pk.key"
    vk_path = proofs / "vk.key"

    if not Path(pk_path).is_file() or not Path(compiled_path).is_file():
        if not onnx_path.is_file():
            export_regex_pii_onnx(onnx_path)
        setup_artifacts(onnx_path, models_dir=models_dir, proofs_dir=proofs_dir)

    timings: dict[str, float] = {}
    data_path = proofs / "input.json"
    witness_path = proofs / "witness.json"
    proof_path_out = str(proofs / proof_filename)

    with open(data_path, "w") as f:
        json.dump({"input_data": encode_output_for_circuit(output_text)}, f)
        f.flush()
    _check_file(Path(data_path), must_be_json=True)
    _check_file(Path(compiled_path), min_size=100)
    _check_file(Path(srs_path), min_size=1)

    try:
        t0 = time.perf_counter()
        ezkl.gen_witness(str(data_path), str(compiled_path), str(witness_path), srs_path=str(srs_path))
        timings["gen_witness_ms"] = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        ezkl.prove(str(witness_path), str(compiled_path), str(pk_path), proof_path=proof_path_out, srs_path=str(srs_path))
        timings["prove_ms"] = (time.perf_counter() - t0) * 1000
    except Exception as e:
        logger.exception("Proof failed")
        return GenerateProofResult(False, timings_ms=timings, error=str(e), output_hash_sha256_hex=compute_output_hash_sha256(output_text))

    return GenerateProofResult(
        True,
        proof_path=proof_path_out,
        vk_path=str(vk_path),
        output_hash_sha256_hex=compute_output_hash_sha256(output_text),
        timings_ms=timings,
    )


def verify_proof(
    proof_path: str | Path,
    models_dir: Path | str | None = None,
    proofs_dir: Path | str | None = None,
) -> bool:
    proof_path = Path(proof_path)
    if not proof_path.is_file():
        return False
    models = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
    proofs = Path(proofs_dir) if proofs_dir else DEFAULT_PROOFS_DIR
    _set_ezkl_env(proofs)
    _ensure_ezkl()
    import ezkl
    return ezkl.verify(str(proof_path), str(models / "settings.json"), str(proofs / "vk.key"), srs_path=str(proofs / "kzg.srs"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["setup", "prove", "verify"])
    parser.add_argument("--onnx", default=None, help="ONNX path for setup/prove (default: regex PII model). Use models/ezkl_example_1l_linear/network.onnx to test if NotPresent is model-specific.")
    parser.add_argument("--text", default="No PII here.", help="For prove")
    parser.add_argument("--proof", default=None, help="For verify")
    parser.add_argument("--models-dir", default=None)
    parser.add_argument("--proofs-dir", default=None)
    args = parser.parse_args()

    if args.onnx:
        onnx_path = Path(args.onnx)
        if not onnx_path.is_absolute():
            onnx_path = (EXPERIMENTS_DIR / onnx_path).resolve()
    else:
        onnx_path = REGEX_PII_ONNX
    if args.action == "setup":
        if not onnx_path.is_file():
            if onnx_path == REGEX_PII_ONNX:
                export_regex_pii_onnx(REGEX_PII_ONNX)
            else:
                raise FileNotFoundError(f"ONNX not found: {onnx_path}")
        paths = setup_artifacts(onnx_path, args.models_dir, args.proofs_dir)
        print("Setup ok:", list(paths.keys()))
    elif args.action == "prove":
        res = generate_proof(args.text, models_dir=args.models_dir, proofs_dir=args.proofs_dir)
        print("success:", res.success, "hash:", res.output_hash_sha256_hex[:16] + "...", "timings:", res.timings_ms)
        if res.error:
            print("error:", res.error)
    else:
        proof = args.proof or str(DEFAULT_PROOFS_DIR / "proof.json")
        print("verified:", verify_proof(proof, args.models_dir, args.proofs_dir))
