# Toolchain Pinning Plugin

A Gradle settings plugin that pins the JDK used for compilation by downloading a specific version
from the [Eclipse Adoptium (Temurin)](https://adoptium.net/) API.

## Overview

When `-PtoolchainJdkVersion` is specified, this plugin:

1. **Configures Gradle Toolchains** on all Java projects with the corresponding major version
2. **Downloads the specified JDK** from the Adoptium API if not already cached
3. **Disables local JDK auto-detection** when an exact version is specified, ensuring the
   pinned version is always used

This overrides any toolchain configuration in `build.gradle.kts`. When `toolchainJdkVersion` is
not set, the plugin does nothing and the build uses whatever JDK is available in the environment.

Downloaded JDKs are cached in `~/.gradle/jdks/` and reused across builds.

## Configuration

The plugin is applied in `settings.gradle.kts`:

```kotlin
pluginManagement {
    includeBuild("toolchain-pinning-plugin")
}

plugins {
    id("com.webauthn4j.toolchain-pinning")
}

toolchainPinning {
    toolchainJdkVersion = providers.gradleProperty("toolchainJdkVersion")
}
```

## Usage

### Use the environment JDK (default)

```sh
./gradlew build
```

No `toolchainJdkVersion` property is set. Gradle uses whatever JDK is available in the environment
(e.g., `JAVA_HOME` or the JDK set up by CI). No download occurs.

### Download the latest JDK for a major version

```sh
./gradlew build -PtoolchainJdkVersion=21
```

Gradle downloads the **latest Adoptium JDK 21** (if not already cached) and uses it
for the build.

### Download an exact JDK version

```sh
./gradlew build -PtoolchainJdkVersion=25.0.3+9
```

Gradle downloads **exactly JDK 25.0.3+9** from Adoptium and uses it for the build.

## How it works

When `toolchainJdkVersion` is set, the plugin performs three actions:

### 1. Toolchain auto-configuration

The plugin calls `java.toolchain.languageVersion.set(...)` on all projects where the
`java` plugin is applied. This overrides any manually configured toolchain and tells Gradle
which major JDK version is required.

### 2. JDK resolution via Adoptium API

The plugin registers a `JavaToolchainResolver` that constructs download URLs for the
[Adoptium API v3](https://api.adoptium.net/):

- **Exact version** (e.g., `25.0.3+9`): `https://api.adoptium.net/v3/binary/version/jdk-{version}/...`
- **Major version only** (e.g., `21`): `https://api.adoptium.net/v3/binary/latest/{major}/ga/...`

Downloading, extracting, and caching are handled by Gradle itself.

### 3. Local JDK auto-detection bypass

When an exact version is specified (the version string contains a dot), the plugin
automatically disables Gradle's local JDK auto-detection (`org.gradle.java.installations.auto-detect=false`).
This prevents Gradle from using a locally installed JDK with a different patch version.

## Caveats

Do not configure `java.toolchain.languageVersion` manually in `build.gradle.kts` when using
this plugin with `-PtoolchainJdkVersion`. The plugin auto-configures toolchains on all Java
projects, so a manual setting would conflict and may cause the build to use an unexpected
JDK version.

## Supported platforms

| OS      | Architecture |
|---------|-------------|
| Linux   | x64, aarch64 |
| Windows | x64, aarch64 |
| macOS   | x64, aarch64 |
