"""
Full E2E pipeline: prompt → LLM (distilgpt2) → PII filter → ZK proof → verify.

Usage:
    python run_pipeline.py "Tell me about Alice"
    python run_pipeline.py "Hello world" --pii-method transformers
    python run_pipeline.py "Hello world" --llm distilgpt2 --max-tokens 80 --skip-proof
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Allow sibling imports (pii_filter, run_ezkl) when running as a script
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from pii_filter import PIIResult, check_pii  # noqa: E402
from pii_filter import Method as PIIMethod  # noqa: E402
from run_ezkl import GenerateProofResult, generate_proof, verify_proof  # noqa: E402
from run_ezkl import compute_output_hash_sha256  # noqa: E402

logger = logging.getLogger(__name__)

EXPERIMENTS_DIR = _SCRIPTS_DIR.parent
DEFAULT_LOGS_DIR = EXPERIMENTS_DIR / "logs"


# ---------------------------------------------------------------------------
# LLM generation
# ---------------------------------------------------------------------------


def generate_llm_output(
    prompt: str,
    model_name: str = "distilgpt2",
    max_new_tokens: int = 100,
    temperature: float = 1.0,
    top_k: int = 50,
    do_sample: bool = True,
) -> str:
    """
    Generate text with a HuggingFace causal LM.

    Returns only the *newly generated* tokens (prompt is stripped).
    """
    from transformers import AutoModelForCausalLM, AutoTokenizer

    logger.info(
        "Loading LLM '%s' (max_new_tokens=%d, temperature=%.2f)",
        model_name,
        max_new_tokens,
        temperature,
    )
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name)

    inputs = tokenizer(prompt, return_tensors="pt")
    prompt_len = inputs["input_ids"].shape[1]

    outputs = model.generate(
        **inputs,
        max_new_tokens=max_new_tokens,
        do_sample=do_sample,
        temperature=temperature,
        top_k=top_k,
        pad_token_id=tokenizer.eos_token_id,
    )

    # Decode only the new tokens (skip the prompt)
    generated_text = tokenizer.decode(
        outputs[0][prompt_len:], skip_special_tokens=True
    )
    return generated_text


# ---------------------------------------------------------------------------
# Pipeline result
# ---------------------------------------------------------------------------


@dataclass
class PipelineResult:
    """Aggregated result of the full pipeline run."""

    prompt: str
    llm_model: str
    llm_output: str
    output_hash_sha256: str

    pii_method: str
    pii_passed: bool
    pii_matches: list[dict] = field(default_factory=list)

    proof_generated: bool = False
    proof_verified: bool | None = None
    proof_path: str | None = None
    proof_size_bytes: int | None = None
    proof_error: str | None = None

    timings_ms: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run_pipeline(
    prompt: str,
    *,
    llm_model: str = "distilgpt2",
    max_new_tokens: int = 100,
    temperature: float = 1.0,
    pii_method: PIIMethod = "regex",
    pii_api_key: str | None = None,
    skip_proof: bool = False,
) -> PipelineResult:
    """
    End-to-end: prompt → LLM → PII filter → (optional) ZK proof → verify.

    Args:
        prompt:          Text prompt for the LLM.
        llm_model:       HuggingFace model id (default: distilgpt2).
        max_new_tokens:  Max tokens to generate.
        temperature:     Sampling temperature.
        pii_method:      'regex', 'transformers', or 'hf_api'.
        pii_api_key:     HF token override (only for pii_method='hf_api').
        skip_proof:      If True, skip proof generation (useful for testing LLM + filter only).

    Returns:
        PipelineResult with all outputs and timings.
    """
    timings: dict[str, float] = {}

    # ── 1. LLM generation ─────────────────────────────────────────────────
    logger.info("STAGE 1/4 — LLM generation (model=%s)", llm_model)
    t0 = time.perf_counter()
    llm_output = generate_llm_output(
        prompt,
        model_name=llm_model,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
    )
    timings["llm_generation_ms"] = (time.perf_counter() - t0) * 1000
    logger.info("LLM output (%d chars): %.120s…", len(llm_output), llm_output)

    # ── 2. Compute output hash ────────────────────────────────────────────
    output_hash = compute_output_hash_sha256(llm_output)
    logger.info("SHA-256 of output: %s", output_hash[:32] + "…")

    # ── 3. PII filter ─────────────────────────────────────────────────────
    logger.info("STAGE 2/4 — PII filter (method=%s)", pii_method)
    t0 = time.perf_counter()
    pii_result: PIIResult = check_pii(llm_output, method=pii_method, api_key=pii_api_key)
    timings["pii_filter_ms"] = (time.perf_counter() - t0) * 1000
    logger.info("PII result: passed=%s, matches=%d", pii_result.passed, len(pii_result.matches))

    # Start building the result (proof fields filled below if applicable)
    result = PipelineResult(
        prompt=prompt,
        llm_model=llm_model,
        llm_output=llm_output,
        output_hash_sha256=output_hash,
        pii_method=pii_result.method,
        pii_passed=pii_result.passed,
        pii_matches=pii_result.matches,
        timings_ms=timings,
    )

    if not pii_result.passed:
        logger.warning("PII detected — skipping proof generation.")
        return result

    if skip_proof:
        logger.info("--skip-proof set — skipping proof generation.")
        return result

    # ── 4. ZK proof generation ────────────────────────────────────────────
    logger.info("STAGE 3/4 — ZK proof generation (EzKL)")
    t0 = time.perf_counter()
    proof_result: GenerateProofResult = generate_proof(llm_output)
    timings["proof_generation_ms"] = (time.perf_counter() - t0) * 1000
    # Merge ezkl-internal timings
    for k, v in proof_result.timings_ms.items():
        timings[f"ezkl_{k}"] = v

    result.proof_generated = proof_result.success
    result.proof_path = proof_result.proof_path
    result.proof_size_bytes = proof_result.proof_size_bytes
    result.proof_error = proof_result.error

    if not proof_result.success:
        logger.error("Proof generation failed: %s", proof_result.error)
        return result

    # ── 5. Verify proof ───────────────────────────────────────────────────
    logger.info("STAGE 4/4 — Proof verification")
    t0 = time.perf_counter()
    verified = verify_proof(proof_result.proof_path)
    timings["proof_verification_ms"] = (time.perf_counter() - t0) * 1000
    result.proof_verified = verified
    logger.info("Proof verified: %s", verified)

    return result


# ---------------------------------------------------------------------------
# Logging helper — write structured JSON log to experiments/logs/
# ---------------------------------------------------------------------------


def _save_log(result: PipelineResult) -> Path:
    """Persist pipeline result as a JSON file under experiments/logs/."""
    DEFAULT_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    log_path = DEFAULT_LOGS_DIR / f"run_{ts}.json"
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    return log_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="E2E pipeline: prompt → LLM → PII filter → ZK proof → verify",
    )
    parser.add_argument("prompt", nargs="?", default="Tell me about Alice Johnson from New York.")
    parser.add_argument("--llm", default="distilgpt2", help="HuggingFace model id (default: distilgpt2)")
    parser.add_argument("--max-tokens", type=int, default=100)
    parser.add_argument("--temperature", type=float, default=1.0)
    parser.add_argument("--pii-method", choices=["regex", "transformers", "hf_api"], default="regex")
    parser.add_argument("--skip-proof", action="store_true", help="Run LLM + filter only, skip ZK proof")
    parser.add_argument("--no-log", action="store_true", help="Don't write JSON log file")
    args = parser.parse_args()

    result = run_pipeline(
        args.prompt,
        llm_model=args.llm,
        max_new_tokens=args.max_tokens,
        temperature=args.temperature,
        pii_method=args.pii_method,
        skip_proof=args.skip_proof,
    )

    # ── Pretty-print summary to stdout ────────────────────────────────────
    print("\n" + "=" * 60)
    print("PIPELINE RESULT")
    print("=" * 60)
    print(f"  Prompt:          {result.prompt!r}")
    print(f"  LLM model:       {result.llm_model}")
    print(f"  LLM output:      {result.llm_output[:200]}{'…' if len(result.llm_output) > 200 else ''}")
    print(f"  Output SHA-256:  {result.output_hash_sha256}")
    print(f"  PII method:      {result.pii_method}")
    print(f"  PII passed:      {result.pii_passed}")
    if result.pii_matches:
        print(f"  PII matches:     {result.pii_matches}")
    print(f"  Proof generated: {result.proof_generated}")
    if result.proof_verified is not None:
        print(f"  Proof verified:  {result.proof_verified}")
    if result.proof_size_bytes is not None:
        print(f"  Proof size:      {result.proof_size_bytes} bytes")
    if result.proof_error:
        print(f"  Proof error:     {result.proof_error}")
    print(f"  Timings (ms):    {json.dumps(result.timings_ms, indent=4)}")

    # ── Save log ──────────────────────────────────────────────────────────
    if not args.no_log:
        log_path = _save_log(result)
        print(f"  Log saved to:    {log_path}")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    main()
