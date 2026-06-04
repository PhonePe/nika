# Roadmap

Nika is currently focused on Java and cross-file taint analysis, but there are a few obvious areas where we want to take it next.

## Near-Term Priorities

### 1. Business Logic Vulnerability Detection

We want to expand Nika beyond traditional source-to-sink issues and add support for **business logic vulnerabilities**.

That includes cases like:

* missing authorization checks in sensitive workflows,
* logic flaws that only appear when multiple steps are combined.

These problems are harder than classic sink-driven vulnerabilities because they depend on how the application behaves, not just on one risky API. Better coverage here is an important part of the roadmap.

### 2. Broader Language Support

We also want to bring Nika to more languages beyond Java.

The main additions we are planning are:

* **Python**, for common backend services, automation code, and API-driven applications,
* **C/C++**, for native services, system components, and security-sensitive low-level code.

The goal is not just to parse these languages, but to support useful analysis in them: source discovery, sink modeling, propagation tracking, and practical vulnerability reporting.

### 3. Longer-Term Direction

Over time, we also want Nika to work better in codebases with indirect dispatch, heavy framework usage, and application-specific security rules.

That means improving:

* deeper inter-procedural and cross-file reachability,
* better support for framework-driven execution paths,
* improved analysis coverage for workflow and logic-centric security issues.
