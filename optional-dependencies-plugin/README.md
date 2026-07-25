# Optional Dependencies Plugin

A Gradle plugin that adds support for Maven-style optional dependencies.

## Overview

Gradle has no built-in equivalent of Maven's `<optional>true</optional>`. This plugin bridges that
gap by creating an `optional` configuration with the following behavior:

- Dependencies declared as `optional` are available on compile and runtime classpaths during the build
- They are **not** propagated transitively to consumers
- When `maven-publish` is applied, they are automatically added to the generated POM with `<optional>true</optional>`

## Configuration

**settings.gradle.kts** (root project)

```kotlin
pluginManagement {
    includeBuild("optional-dependencies-plugin")
}
```

**build.gradle.kts** (subproject)

```kotlin
plugins {
    id("com.webauthn4j.optional-dependencies")
}

dependencies {
    optional("com.example:some-library:1.0")
}
```

## How it works

1. **Creates an `optional` configuration** with `canBeConsumed = false` and `canBeResolved = false`.
   This makes it a pure dependency bucket that downstream projects cannot access.

2. **Extends compile and runtime classpaths** so that optional dependencies are available during
   compilation and testing, just like `implementation` dependencies.

3. **Hooks into `maven-publish`** to add optional dependencies to the generated POM with
   `<optional>true</optional>`. This ensures Maven consumers can see which dependencies are
   optional and explicitly add them if needed.

## Generated POM

```xml
<dependency>
    <groupId>com.example</groupId>
    <artifactId>some-library</artifactId>
    <version>1.0</version>
    <scope>compile</scope>
    <optional>true</optional>
</dependency>
```

## Requirements

- Gradle 9.0+
- `java` or `java-library` plugin (for classpath integration)
- `maven-publish` plugin (for POM generation; optional — the plugin works without it)
