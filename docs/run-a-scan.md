## CLI Help
Run Nika against a source code repository.

### Usage
`python3 main.py --path <PATH> [--lang <LANG>] [--output <FILE>] [--config <FILE>] [--source_branch <BRANCH>] [--target_branch <BRANCH>]`

### Arguments
- `--path` (required): Path to the source directory or git repository to analyze.
- `--lang` (optional, default: `java`, choices: `java`): Programming language of the codebase.
- `--output` (optional, default: `report.html`): Path to save the HTML report.
- `--config` (optional, default: `config/crtConfig.yml`): Path to the YAML config file.
- `--source_branch` (optional, default: `None`): Branch to analyze in the git repository.
- `--target_branch` (optional, default: `None`): Branch to compare against in the git repository.

## Examples

You can use the examples below as-is, or combine them depending on how you want to review the codebase.
AI-enabled review can be used with any of these scan modes, including basic, diff-aware, and aggressive scans.

### Basic Scan

Use this when you want to run a standard scan across the codebase.

```bash
python3 main.py --path /path/to/source --lang java --output report.html
```

### Diff Aware Scan

Use this when you want to focus on changes introduced in a branch instead of scanning everything equally.

```bash
python3 main.py --path /path/to/source --lang java --output report.html --source_branch sourceBranchName --target_branch targetBranchName
```

### Aggressive Scan

Use this when the codebase has deeper or less direct data flows and you want broader reachability analysis.

First, enable aggressive scan in `crtConfig.yml`.

```yaml
aggressiveScan: true
```

Then run the scan as usual.

```bash
python3 main.py --path /path/to/source --lang java --output report.html
```

### AI Enabled False Positive Scan

Use this when you want Nika to review findings with the LLM-assisted stage and help reduce false positives.

First, enable LLM review in `crtConfig.yml`.

```yaml
LLMConfig:
  API_KEY: 'API_TOKEN'
  LLM_URL: 'https://chatgpt.com/api/v1'
  MODEL: 'GPT-5'
  MAX_TOOL_CALLS: 10
  MAX_ITERATIONS: 15
  RECURSION_LIMIT: 100
  PROMPT_COST_PER_MILLION: 1.25
  COMPLETION_COST_PER_MILLION: 10.0

llm_review_enabled: true
```

Then run the scan command that fits your use case. You can use the same AI-enabled review with the basic, diff-aware, or aggressive examples above.

```bash
python3 main.py --path /path/to/source --lang java --output report.html
```