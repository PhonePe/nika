

## Minimum Requirements

| Component | Supported Versions |
|------------|-------------------|
| Operating System | macOS, Linux |
| Python | 3.10+ |
| RAM | 4 GB minimum (8 GB recommended) |
| Disk Space | 4 GB available |
| Architecture | x86_64, ARM64 |
| Library | coreutils |


## Run via Docker

You can use pre-built docker images.

```bash
docker pull ghcr.io/phonepe/nika:latest
export NIKA_IMAGE=ghcr.io/phonepe/nika
./run.sh --path /absolute/path/to/code --config /absolute/path/to/crtConfig.yml --output ./report.html
```

or build a docker image yourself.

```bash
git clone https://github.com/PhonePe/nika.git
cd nika
./build.sh
./run.sh --path /absolute/path/to/code --config /absolute/path/to/crtConfig.yml --output ./report.html
```

## Run locally

```bash
git clone https://github.com/PhonePe/nika.git
cd nika
./native-build.sh
./native-run.sh --path /absolute/path/to/code --output ./report.html
```

## Enable AI based False Positive Analysis

* Docker Setup - You can modify the config at /absolute/path/to/crtConfig.yml.
* Local Setup - You can modify the config at /absolute/path/to/native-crtConfig.yml.

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

llm_review_enabled: false
```