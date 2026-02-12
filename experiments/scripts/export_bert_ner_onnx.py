"""
Export Hugging Face BERT NER (token classification) to ONNX for use with EzKL.

Model: dbmdz/bert-large-cased-finetuned-conll03-english (CoNLL-03 NER).
Exports with fixed shapes: batch=1, seq_len=SEQ_LEN (default 128) for compatibility with ezkl.
Saves ONNX and tokenizer to models/bert_ner_conll03/.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

EXPERIMENTS_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MODELS_DIR = EXPERIMENTS_DIR / "models"
BERT_NER_DIR = DEFAULT_MODELS_DIR / "bert_ner_conll03"
DEFAULT_SEQ_LEN = 128
MODEL_ID = "dbmdz/bert-large-cased-finetuned-conll03-english"


def export_bert_ner_onnx(
    out_dir: Path | str = BERT_NER_DIR,
    seq_len: int = DEFAULT_SEQ_LEN,
    opset_version: int = 13,
) -> Path:
    """
    Download the BERT NER model and export to ONNX with fixed input shapes.
    Saves: model.onnx, tokenizer config (via save_pretrained), input_config.json.

    Uses opset 13 by default: tract/ezkl "Translating proto model to model" errors
    are known for opset <= 12; use >= 13. If gen_settings still fails, tract may not
    support some BERT ops (try regex ONNX or a smaller NER model).
    """
    import torch
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    onnx_path = out_dir / "model.onnx"

    logger.info("Loading model and tokenizer: %s", MODEL_ID)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForTokenClassification.from_pretrained(MODEL_ID)
    model.eval()

    # Dummy inputs with fixed shape [1, seq_len]
    batch_size = 1
    dummy_input_ids = torch.randint(0, tokenizer.vocab_size, (batch_size, seq_len), dtype=torch.long)
    dummy_attention_mask = torch.ones(batch_size, seq_len, dtype=torch.long)
    dummy_token_type_ids = torch.zeros(batch_size, seq_len, dtype=torch.long)

    input_names = ["input_ids", "attention_mask", "token_type_ids"]
    output_names = ["logits"]

    logger.info("Exporting to ONNX (seq_len=%s)...", seq_len)
    torch.onnx.export(
        model,
        (dummy_input_ids, dummy_attention_mask, dummy_token_type_ids),
        str(onnx_path),
        input_names=input_names,
        output_names=output_names,
        dynamic_axes=None,  # fully fixed for ezkl
        opset_version=opset_version,
    )

    # Save tokenizer so run_ezkl can encode text
    tokenizer.save_pretrained(out_dir)

    # Save input config for run_ezkl (shapes and dtypes)
    input_config = {
        "input_names": input_names,
        "output_names": output_names,
        "seq_len": seq_len,
        "batch_size": batch_size,
    }
    with open(out_dir / "input_config.json", "w") as f:
        json.dump(input_config, f, indent=2)

    logger.info("Saved ONNX to %s", onnx_path)
    return onnx_path


def encode_text_for_bert_ner(text: str, tokenizer, seq_len: int = DEFAULT_SEQ_LEN) -> list[list[list[int]]]:
    """
    Encode text for the BERT ONNX: returns [input_ids, attention_mask, token_type_ids]
    each of shape [1, seq_len]. Used to build input_data JSON for ezkl.
    """
    enc = tokenizer(
        text,
        return_tensors="pt",
        padding="max_length",
        max_length=seq_len,
        truncation=True,
    )
    return [
        enc["input_ids"].tolist(),
        enc["attention_mask"].tolist(),
        enc["token_type_ids"].tolist(),
    ]


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Export BERT NER to ONNX for EzKL.")
    parser.add_argument("--opset", type=int, default=13, help="ONNX opset (13+ avoids tract translation errors; try 11 if export fails)")
    parser.add_argument("--seq-len", type=int, default=DEFAULT_SEQ_LEN)
    args = parser.parse_args()
    export_bert_ner_onnx(seq_len=args.seq_len, opset_version=args.opset)
    print("Done. ONNX at:", BERT_NER_DIR / "model.onnx")
