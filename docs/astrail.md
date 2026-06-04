# Astrail

We have created Astrail which is a Java-focused fork of [Joern](https://joern.io/).

Nika uses Astrail because many real vulnerabilities are not visible from one file or one method alone. In a typical Java application, untrusted input may move through controllers, services, helpers, and indirect method calls before it reaches a dangerous sink.

Nika uses Astrail instead of plain Joern because Astrail is trimmed specifically for Java and adds pointer-analysis-backed call resolution. That makes it a better fit for Nika's use case, where the goal is to recover Java call paths and source-to-sink flows with higher precision instead of supporting many languages more generally.

Astrail helps Nika follow those paths more reliably. It builds the code property graph for the project, resolves calls more accurately, and makes it possible to trace data flow across files and methods. This gives Nika a better chance of finding the full path from a source to a sink instead of reporting an isolated risky call.

If you want to look at the project directly, the Astrail repository is available here: [https://github.com/rootaux/astrail](https://github.com/rootaux/astrail).
