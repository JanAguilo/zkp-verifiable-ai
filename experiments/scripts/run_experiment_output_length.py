"""
Experiment: vary attested output length L (128, 256, 512, 1024, 2048) for the same reference text.

For each L:
- If L < output byte length: attest only the prefix (first L bytes); print warning.
- Run PII filter on the attested text; if passed, generate and verify ZK proof with that L.
- Log per-L results (truncated, pii_passed, proof success, proof size, timings) to
  experiments/logs/output_length/run_YYYYMMDD_HHMMSS.json.

Usage:
    python run_experiment_output_length.py --prompt "Tell me about the weather"
    python run_experiment_output_length.py --text-file data/sample_output.txt
    python run_experiment_output_length.py --text "No PII here." --lengths 128 256
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Sibling imports
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from pii_filter import check_pii  # noqa: E402
from pii_filter import Method as PIIMethod  # noqa: E402
from run_ezkl import (  # noqa: E402
    DEFAULT_MODELS_DIR,
    DEFAULT_PROOFS_DIR,
    export_regex_pii_onnx,
    generate_proof,
    verify_proof,
)
from run_pipeline import generate_llm_output  # noqa: E402

logger = logging.getLogger(__name__)

EXPERIMENTS_DIR = _SCRIPTS_DIR.parent
OUTPUT_LENGTH_LOGS_DIR = EXPERIMENTS_DIR / "logs" / "output_length"
DEFAULT_LENGTHS = [128, 256, 512, 1024, 2048]


def get_reference_output(
    *,
    prompt: str | None = None,
    text: str | None = None,
    text_file: Path | str | None = None,
    llm_model: str = "distilgpt2",
    max_new_tokens: int = 2500,
    min_new_tokens: int = 0,
) -> str:
    """Resolve a single reference output from --prompt, --text, or --text-file (first wins)."""
    if text is not None and text.strip():
        return text.strip()
    if text_file is not None:
        path = Path(text_file)
        if not path.is_file():
            raise FileNotFoundError(f"Text file not found: {path}")
        return path.read_text(encoding="utf-8").strip()
    if prompt is not None:
        return generate_llm_output(
            prompt,
            model_name=llm_model,
            max_new_tokens=max_new_tokens,
            min_new_tokens=min_new_tokens,
        )
    raise ValueError("Provide one of: --prompt, --text, or --text-file")


def run_one_L(
    L: int,
    reference_output: str,
    output_byte_len: int,
    pii_method: PIIMethod,
    skip_proof: bool,
) -> dict:
    """Run PII check and (optionally) proof for one value of L. Returns result dict for logging."""
    # Attest prefix of length L bytes if L < full length
    raw_bytes = reference_output.encode("utf-8")
    if L < output_byte_len:
        attested_text = raw_bytes[:L].decode("utf-8", errors="ignore")
        print("WARNING: L < output length, only prefix will be attested.")
    else:
        attested_text = reference_output

    # Per-L artifact dirs
    models_dir = DEFAULT_MODELS_DIR / "output_length" / f"L{L}"
    proofs_dir = DEFAULT_PROOFS_DIR / "output_length" / f"L{L}"
    onnx_path = models_dir / "regex_pii.onnx"
    models_dir.mkdir(parents=True, exist_ok=True)
    proofs_dir.mkdir(parents=True, exist_ok=True)

    # Ensure ONNX exists for this L
    if not onnx_path.is_file():
        export_regex_pii_onnx(onnx_path, max_len=L)

    # PII check on attested text
    t0 = time.perf_counter()
    pii_result = check_pii(attested_text, method=pii_method)
    pii_ms = (time.perf_counter() - t0) * 1000

    result = {
        "L": L,
        "output_byte_len": output_byte_len,
        "attested_byte_len": min(L, output_byte_len),
        "truncated": L < output_byte_len,
        "pii_passed": pii_result.passed,
        "pii_matches_count": len(pii_result.matches),
        "pii_filter_ms": round(pii_ms, 2),
        "proof_generated": False,
        "proof_verified": None,
        "proof_size_bytes": None,
        "proof_error": None,
        "timings_ms": {},
    }

    if not pii_result.passed:
        return result

    if skip_proof:
        return result

    # Generate proof with L-specific paths and max_len
    proof_result = generate_proof(
        attested_text,
        onnx_path=onnx_path,
        models_dir=models_dir,
        proofs_dir=proofs_dir,
        proof_filename="proof.json",
        max_len=L,
    )
    result["proof_generated"] = proof_result.success
    result["proof_size_bytes"] = proof_result.proof_size_bytes
    result["proof_error"] = proof_result.error
    result["timings_ms"] = dict(proof_result.timings_ms)

    if proof_result.success and proof_result.proof_path:
        t0 = time.perf_counter()
        verified = verify_proof(proof_result.proof_path, models_dir=models_dir, proofs_dir=proofs_dir)
        result["proof_verification_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        result["proof_verified"] = verified

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Experiment: same output text, varying attested length L (128, 256, 512, 1024, 2048).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prompt", type=str, help="Run LLM once with this prompt and use its output as reference.")
    group.add_argument("--text", type=str, help="Use this string as the reference output.")
    group.add_argument("--text-file", type=str, metavar="PATH", help="Read reference output from file.")
    parser.add_argument("--lengths", type=int, nargs="+", default=DEFAULT_LENGTHS, help=f"L values to sweep (default: {DEFAULT_LENGTHS})")
    parser.add_argument("--pii-method", choices=["regex", "transformers", "hf_api"], default="regex")
    parser.add_argument("--skip-proof", action="store_true", help="Only run PII filter per L, skip ZK proof.")
    parser.add_argument("--llm", default="distilgpt2", help="For --prompt: HuggingFace model id.")
    parser.add_argument("--max-tokens", type=int, default=2500, help="For --prompt: max new tokens from the LLM. Default 2500; pipeline hard-caps at 2048 bytes.")
    parser.add_argument("--min-tokens", type=int, default=1800, help="For --prompt: min new tokens the LLM must produce before it can stop (prevents early EOS). Default 1800 targets ~1900 bytes.")
    parser.add_argument("--no-log", action="store_true", help="Do not write JSON log file.")
    args = parser.parse_args()

    # Resolve reference output
    logger.info("Resolving reference output...")
    reference_output = get_reference_output(
        prompt=args.prompt,
        text=args.text,
        text_file=args.text_file,
        llm_model=args.llm,
        max_new_tokens=args.max_tokens,
        min_new_tokens=args.min_tokens,
    )
    output_byte_len = len(reference_output.encode("utf-8"))
    logger.info("Reference output length: %d bytes", output_byte_len)

    # Run each L
    results = []
    for L in sorted(args.lengths):
        logger.info("--- L = %d ---", L)
        res = run_one_L(
            L,
            reference_output,
            output_byte_len,
            pii_method=args.pii_method,
            skip_proof=args.skip_proof,
        )
        results.append(res)
        print(f"  L={L} truncated={res['truncated']} pii_passed={res['pii_passed']} proof_generated={res['proof_generated']} proof_verified={res.get('proof_verified')}")

    # Summary
    out = {
        "reference_source": "prompt" if args.prompt else ("text" if args.text else "text_file"),
        "output_byte_len": output_byte_len,
        "pii_method": args.pii_method,
        "skip_proof": args.skip_proof,
        "lengths": args.lengths,
        "results": results,
    }
    if args.prompt is not None:
        out["llm_model"] = args.llm
        out["max_tokens"] = args.max_tokens
        out["min_tokens"] = args.min_tokens
    print("\n" + "=" * 60)
    print("OUTPUT LENGTH EXPERIMENT SUMMARY")
    print("=" * 60)
    print(json.dumps(out, indent=2, ensure_ascii=False))

    if not args.no_log:
        OUTPUT_LENGTH_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        log_path = OUTPUT_LENGTH_LOGS_DIR / f"run_{ts}.json"
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"\nLog saved to: {log_path}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    main()
