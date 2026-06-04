# Nika

Nika is an open-source source code review and static analysis tool for security engineers who need to identify realistic exploit paths in Java applications. It performs cross-file taint analysis to trace attacker-controlled input across application layers and determine whether that input reaches a security-sensitive sink.

## Why Nika

Many exploitable issues are not visible inside a single file. Request data may enter through a controller, pass through DTOs and service layers, and only become dangerous when it reaches a sink such as a database query, file operation, template engine, reflection API, or outbound network call.

Nika is built for that review problem. Instead of stopping at isolated risky APIs, it follows the flow across files and functions so security engineers can evaluate whether a path is actually reachable.

## What Nika Helps Security Engineers Do

- Trace attacker-controlled input across controllers, services, helpers, and utility layers.
- Validate source-to-sink reachability instead of reviewing disconnected sink matches.
- Focus on code under review with branch-aware scanning.
- Recover harder-to-resolve flows with aggressive reachability mode.
- Generate HTML reports that are easier to review and share.
- Extend coverage with custom sources, OpenGrep sinks, and vulnerability plugins.

## Detection Coverage

Nika currently documents support for the following vulnerability categories in Java codebases:

- SQL injection
- SSRF
- Path traversal
- Command injection
- Code injection
- Template injection
- Deserialization
- XXE
- Cryptographic failures
- Unsafe reflection
- Security-critical call-order violations in sensitive execution flows and validation chains

## How Nika Works

At a high level, Nika follows this analysis flow:

1. Process the target repository into an analysis representation that captures code structure, control flow, and data flow.
2. Identify configured sources where attacker-controlled input enters the application.
3. Identify sinks that represent security-sensitive operations.
4. Perform cross-file and inter-procedural analysis to determine whether input can reach those sinks.
5. Optionally review traces to reduce false positives.
6. Produce an HTML report with the vulnerable path, affected code locations, and remediation context.

## Quick Start

### Native Scan

Use this when you want a local Python environment and faster local execution.

```bash
git clone https://github.com/PhonePe/nika.git
cd nika
./native-build.sh
./native-run.sh --path /absolute/path/to/code --output ./report.html
```

### Container Scan

Use this when you want an isolated runtime packaged into a Docker image.

```bash
git clone https://github.com/PhonePe/nika.git
cd nika
./build.sh
./run.sh --path /absolute/path/to/code --config /absolute/path/to/crtConfig.yml --output ./report.html
```

Or you can use a pre-built image

```bash
docker pull ghcr.io/phonepe/nika:latest
export NIKA_IMAGE=ghcr.io/phonepe/nika
./run.sh --path /absolute/path/to/code --config /absolute/path/to/crtConfig.yml --output ./report.html
```

## When To Use Each Mode

### Native Scan

Choose native execution when you want the quickest local setup for repeated analysis on a workstation or CI runner that already meets the tool requirements.

### Container Scan

Choose container execution when you want a more isolated runtime and a packaged scan environment with fewer local tool dependencies.

### Branch-Aware Scan

Use branch-aware scanning when reviewing a feature branch, pull request, or release candidate and you want findings aligned with the branch diff. Nika compares the source and target branches to identify the baseline commit instead of treating the entire repository as equally new.

Example:

```bash
python3 main.py --path "/absolute/path/to/git/repo" --lang java --source_branch feature-branch --target_branch main --output report.html
```

### Aggressive Scan

Enable `aggressiveScan` when the default reachability pass is too shallow for the target codebase, especially in applications with layered interfaces, framework callbacks, or complex virtual dispatch. `aggressiveScan` switches to method-level reachability checks so it can recover flows the normal pass may miss.


## Language Support

Nika currently supports Java. Java is the only fully supported language today; support for other languages remains planned.