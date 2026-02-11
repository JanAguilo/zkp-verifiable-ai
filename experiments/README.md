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

## EzKL example model (default)

For a **working proof pipeline** without a custom PII ONNX, the repo uses the [EzKL 1l_linear example](https://github.com/zkonduit/ezkl/tree/main/examples/onnx/1l_linear): a minimal ONNX that is known to work with EzKL. It is stored under `models/ezkl_example_1l_linear/` (download from the EzKL repo if missing). Commands use this by default:

- `python scripts/run_ezkl.py check` — compatibility check
- `python scripts/run_ezkl.py setup` — generate settings, compile, keys
- `python scripts/run_ezkl.py prove --text "No PII here."` — generate proof
- `python scripts/run_ezkl.py verify` — verify proof

For **real PII filtering**, point to your ONNX with `--onnx` (e.g. `models/roberta_pii/model.onnx` or `models/ner_bert/model.onnx`) once those models are compatible with EzKL.

### SRS (Structured Reference String)

`setup` and `prove` require a `kzg.srs` file in `proofs/`. The script tries to download it via `ezkl.get_srs()`; on some environments (e.g. Windows) that can fail with "no running event loop". In that case either:

- Run the EzKL CLI where available: `ezkl get-srs` (or `python -m ezkl get-srs` if `ezkl` is not on PATH) and copy `kzg.srs` into `experiments/proofs/`, or  
- Use a Linux/WSL or CI environment where `get_srs` works.

Using `gen_srs` locally (automatic fallback when `get_srs` fails) is for testing only and may cause `setup` to panic; use a proper downloaded SRS for full setup/prove.

### Trying another ezkl version

If `setup` panics with `NotPresent` (ezkl 23.x on Windows), try an older release:

```bash
pip uninstall ezkl
pip install ezkl==22.2.1
# or: pip install ezkl==22.0.1
```

Then run `python scripts/run_ezkl.py setup` again. The project pins `ezkl==22.2.1` in `requirements.txt` by default for compatibility; change the version there if you need a different one.

**If you see `expected value, line: 1, column: 1`** (or similar JSON parse errors in the Rust panic): that usually means ezkl read a file expecting JSON and got empty or invalid content. The script now validates that `settings.json`, `input.json`, the compiled circuit, and SRS exist and are non-empty before calling ezkl; fix any missing or empty files it reports.

**Where to find the full panic and stack trace:** Run the failing command and look at the same terminal (scroll up if needed). To save it to a file:  
`python scripts/run_ezkl.py setup 2>&1 | Tee-Object -FilePath panic_log.txt`  
Then share the contents of `panic_log.txt` (including the `thread '...' panicked at ...` line and the Python traceback).

**Testing if NotPresent is specific to our ONNX:** The panic happens during `setup` after “model layout…”, often when a tensor shape is `NotPresent`. To see if it’s our regex ONNX vs ezkl in general, run setup with the official 1l_linear example (if present):  
`python scripts/run_ezkl.py setup --onnx models/ezkl_example_1l_linear/network.onnx`  
If that succeeds, the issue is likely our model/circuit; if it also panics, it’s likely environment or ezkl.

### Windows: NotPresent during setup/prove (known ezkl issue)

EzKL is known to panic with `NotPresent` on **Windows** during `setup` and `prove` while the same steps work on **Linux/Ubuntu** (see [zkonduit/ezkl issues](https://github.com/zkonduit/ezkl/issues)). Workarounds:

1. **Env vars (try first)**  
   The script now sets `EZKL_REPO_PATH`, `EZKL_WORKING_DIR`, and (on Windows) `HOME` before calling ezkl. To try a custom path manually in PowerShell (current session only):
   ```powershell
   $env:EZKL_REPO_PATH = "C:\path\to\experiments\proofs\.ezkl"
   $env:EZKL_WORKING_DIR = "C:\path\to\experiments\proofs"
   python scripts/run_ezkl.py setup
   ```
   To set permanently: [Environment]::SetEnvironmentVariable("EZKL_REPO_PATH", "C:\...\proofs\.ezkl", "User")

2. **Use Linux or WSL**  
   Run the full pipeline (setup → prove → verify) in WSL or a Linux box; copy `proofs/` and `models/` back if needed.



