"""
EzKL proof for regex-based PII filter: build ONNX from regex logic, then prove/verify.

- Export regex PII logic to a small ONNX (input [1, L] bytes, L=2048 -> output: PII count).
- Setup: gen_settings, compile, get_srs, setup.
- Prove: encode full output (up to L bytes) -> witness -> proof (bound to hash of output).
- Verify: check proof with vk/settings/srs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
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
SETUP_LOGS_DIR = EXPERIMENTS_DIR / "logs" / "setup"
REGEX_PII_ONNX = DEFAULT_MODELS_DIR / "regex_pii.onnx"
# Official EzKL example; use with --onnx to test if setup works (isolates NotPresent to our ONNX or ezkl)
EXAMPLE_1L_LINEAR_ONNX = DEFAULT_MODELS_DIR / "ezkl_example_1l_linear" / "network.onnx"
# Maximum UTF-8 byte length for LLM output; circuit sees the whole output up to this bound.
MAX_LEN = 2048


# ---------------------------------------------------------------------------
# Regex PII -> ONNX
# ---------------------------------------------------------------------------


def export_regex_pii_onnx(onnx_path: str | Path, max_len: int = MAX_LEN) -> Path:
    """
    Build a minimal ONNX that encodes regex-PII detection: input [1, max_len] float (bytes/255),
    output [1, 1] = count of 'suspicious' bytes (e.g. @ for email). Pass = output 0.
    """
    import torch
    import torch.nn as nn

    class RegexPIIModule(nn.Module):
        # Detect bytes that often appear in PII: @ (64), digits 0-9 (48-57), - (45), . (46)
        SUSPICIOUS = (64, 45, 46) + tuple(range(48, 58))

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            # x: [1, max_len], values in [0, 1] (byte/255)
            out = torch.zeros(x.shape[0], 1, dtype=x.dtype, device=x.device)
            for b in self.SUSPICIOUS:
                out = out + (x == (b / 255.0)).to(x.dtype).sum(dim=1, keepdim=True)
            return out

    model = RegexPIIModule()
    model.eval()
    dummy = torch.rand(1, max_len)
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


def _is_bert_ner_onnx(onnx_path: Path) -> bool:
    """True if ONNX dir has input_config.json (BERT NER export)."""
    return (Path(onnx_path).parent / "input_config.json").is_file()


def _encode_input_for_onnx(onnx_path: Path, text: str, for_setup: bool = False, max_len: int | None = None) -> list:
    """
    Return input_data payload for ezkl (list of arrays). For regex/1l_linear a single array;
    for BERT NER, list of [input_ids, attention_mask, token_type_ids].
    When max_len is set, regex encoding uses that length (for per-L experiments).
    """
    onnx_path = Path(onnx_path)
    use_1l_linear = EXAMPLE_1L_LINEAR_ONNX.resolve() == onnx_path.resolve()
    if use_1l_linear:
        return [[0.0]]
    if _is_bert_ner_onnx(onnx_path):
        import torch
        from transformers import AutoTokenizer
        with open(onnx_path.parent / "input_config.json") as f:
            cfg = json.load(f)
        seq_len = int(cfg.get("seq_len", 128))
        tokenizer = AutoTokenizer.from_pretrained(str(onnx_path.parent))
        enc = tokenizer(
            text,
            return_tensors="pt",
            padding="max_length",
            max_length=seq_len,
            truncation=True,
        )
        token_type_ids = enc.get("token_type_ids")
        if token_type_ids is None:
            token_type_ids = torch.zeros_like(enc["input_ids"], dtype=torch.long)
        return [
            enc["input_ids"].tolist(),
            enc["attention_mask"].tolist(),
            token_type_ids.tolist(),
        ]
    return encode_output_for_circuit(text, max_len=max_len or MAX_LEN)


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
    proof_size_bytes: int | None = None
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
    max_len: int | None = None,
    log_costs: bool = True,
) -> dict[str, str]:
    """Gen settings, compile circuit, get SRS, setup (key generation). Returns paths. Logs costs to logs/setup/ if log_costs. When max_len is set (for regex ONNX), dummy input uses that length."""
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

    costs: dict[str, float] = {}  # step -> seconds

    run_args = ezkl.PyRunArgs()
    run_args.input_visibility = "hashed/public"
    run_args.output_visibility = "public"
    run_args.param_visibility = "fixed"

    t0 = time.perf_counter()
    ezkl.gen_settings(str(onnx_path), str(settings_path), run_args)
    costs["gen_settings_sec"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    ezkl.compile_circuit(str(onnx_path), str(compiled_path), str(settings_path))
    costs["compile_circuit_sec"] = time.perf_counter() - t0

    # Run get_srs + SRS wait + gen_witness + setup inside one event loop (sync calls, no await).
    import asyncio

    async def _run_setup_with_loop() -> None:
        t0 = time.perf_counter()
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
            costs["get_srs_sec"] = time.perf_counter() - t0
            costs["srs_source"] = "gen_srs"
        elif srs_file.stat().st_size < 1_000_000:
            logger.warning("SRS file too small; generating locally (gen_srs).")
            with open(settings_path) as f:
                logrows = int(json.load(f).get("run_args", {}).get("logrows", 17))
            ezkl.gen_srs(str(srs_path), logrows)
            costs["get_srs_sec"] = time.perf_counter() - t0
            costs["srs_source"] = "gen_srs"
        else:
            costs["get_srs_sec"] = time.perf_counter() - t0
            costs["srs_source"] = "download"  # already existed or just downloaded

        _check_file(settings_path, must_be_json=True)
        _check_file(compiled_path, min_size=100)
        _check_file(srs_path, min_size=1)
        dummy_data = proofs / "input.json"
        input_payload = _encode_input_for_onnx(onnx_path, "", for_setup=True, max_len=max_len)
        with open(dummy_data, "w") as f:
            json.dump({"input_data": input_payload}, f)
            f.flush()
        _check_file(dummy_data, must_be_json=True)
        setup_witness = proofs / "setup_witness.json"

        t0 = time.perf_counter()
        ezkl.gen_witness(str(dummy_data), str(compiled_path), str(setup_witness), srs_path=str(srs_path))
        costs["gen_witness_sec"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        ezkl.setup(str(compiled_path), str(vk_path), str(pk_path), srs_path=str(srs_path))
        costs["setup_keys_sec"] = time.perf_counter() - t0

    asyncio.run(_run_setup_with_loop())

    costs["total_sec"] = sum(v for k, v in costs.items() if k.endswith("_sec"))
    if log_costs:
        SETUP_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = SETUP_LOGS_DIR / f"run_{run_id}.json"
        costs_sec = {k: round(v, 4) for k, v in costs.items() if k.endswith("_sec")}
        log_entry = {
            "run_id": run_id,
            "onnx_path": str(onnx_path),
            "models_dir": str(models),
            "proofs_dir": str(proofs),
            "costs_sec": costs_sec,
            "srs_source": costs.get("srs_source", "unknown"),
        }
        with open(log_path, "w") as f:
            json.dump(log_entry, f, indent=2)
        logger.info("Setup costs logged to %s", log_path)

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
    max_len: int | None = None,
) -> GenerateProofResult:
    """Encode output, gen witness, prove. Runs setup if keys missing. When max_len is set, regex encoding and (if needed) ONNX export use that length (for per-L experiments)."""
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
        if not onnx_path.is_file() and max_len is not None:
            export_regex_pii_onnx(onnx_path, max_len=max_len)
        elif onnx_path == REGEX_PII_ONNX:
            export_regex_pii_onnx(REGEX_PII_ONNX)
        elif not onnx_path.is_file():
            raise FileNotFoundError(
                f"ONNX not found: {onnx_path}. For BERT NER run: python scripts/export_bert_ner_onnx.py"
            )
        setup_artifacts(onnx_path, models_dir=models_dir, proofs_dir=proofs_dir, max_len=max_len)

    timings: dict[str, float] = {}
    data_path = proofs / "input.json"
    witness_path = proofs / "witness.json"
    proof_path_out = str(proofs / proof_filename)

    with open(data_path, "w") as f:
        json.dump({"input_data": _encode_input_for_onnx(onnx_path, output_text, max_len=max_len)}, f)
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

    proof_size = Path(proof_path_out).stat().st_size if Path(proof_path_out).is_file() else None
    return GenerateProofResult(
        True,
        proof_path=proof_path_out,
        vk_path=str(vk_path),
        output_hash_sha256_hex=compute_output_hash_sha256(output_text),
        proof_size_bytes=proof_size,
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
        if not args.models_dir:
            args.models_dir = str(onnx_path.parent)
        if not args.proofs_dir:
            args.proofs_dir = str(DEFAULT_PROOFS_DIR / onnx_path.parent.name)
    else:
        onnx_path = REGEX_PII_ONNX
    if args.action == "setup":
        if onnx_path == REGEX_PII_ONNX:
            # Always re-export so ONNX input shape matches current MAX_LEN (e.g. 2048)
            export_regex_pii_onnx(REGEX_PII_ONNX)
        elif not onnx_path.is_file():
            raise FileNotFoundError(
                f"ONNX not found: {onnx_path}. For BERT NER run: python scripts/export_bert_ner_onnx.py"
            )
        paths = setup_artifacts(onnx_path, args.models_dir, args.proofs_dir)
        print("Setup ok:", list(paths.keys()))
    elif args.action == "prove":
        res = generate_proof(
            args.text,
            onnx_path=onnx_path,
            models_dir=args.models_dir,
            proofs_dir=args.proofs_dir,
        )
        print("success:", res.success, "hash:", res.output_hash_sha256_hex[:16] + "...", "timings:", res.timings_ms)
        if res.error:
            print("error:", res.error)
    else:
        proof = args.proof or str(DEFAULT_PROOFS_DIR / "proof.json")
        print("verified:", verify_proof(proof, args.models_dir, args.proofs_dir))
