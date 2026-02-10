# Experiments

# ZK-PII Proofs for LLM Outputs

This project demonstrates a privacy-preserving system that proves — using zero-knowledge proofs (ZKPs) — that the output of a language model (LLM) does **not contain personally identifiable information (PII)**, without revealing the output or the filtering model itself.

## Core Workflow

1. A user submits a prompt.
2. A small LLM (e.g., GPT-2) generates a response.
3. A PII filter (e.g., ONNX NER model) checks if the output contains PII.
4. If clean, a zero-knowledge proof is generated using [EzKL](https://github.com/zkonduit/ezkl) to certify:
   - The PII model was applied
   - The output passed the filter
   - The proof is **bound** to a hash of the actual output
5. The verifier can confirm the output was safe — without ever seeing it.



