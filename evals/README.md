# evals/

The **small-model tool-calling evaluation harness**. It points a real local
model (GPT-OSS, Gemma 4, Qwen3 — served via vLLM or llama.cpp's
OpenAI-compatible endpoint) at a server's tools and measures **callability**:

- **Tool-selection accuracy** — given a natural-language task, is the right tool chosen?
- **Argument-filling success rate** — are arguments populated correctly across N runs?
- **Degradation signals** — tools that score poorly (too many tools, oversized
  enums, nested args) are flagged as **design defects to fix**, reported as
  success rates rather than pass/fail.

Task sets live here as YAML. Run outputs are written to `results/` (gitignored).
A tool that passes contract tests but fails here has a design problem — simplify
the schema, do not lower the bar.
