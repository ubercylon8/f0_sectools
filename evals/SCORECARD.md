# Small-model tool-calling scorecard

_Pending the first live sweep. Generate with:_

```
uv run python -m evals.scorecard --base-url http://localhost:11434/v1 --runs 1
```

Each cell will be **tool-selection% / argument-filling%** per server, with an `all`
column for the combined 22-tool registry (the composition test).
