# maven-central-publish-plugin

A lightweight Gradle plugin that publishes artifacts to Maven Central via the [Central Portal Publisher API](https://central.sonatype.org/publish/publish-portal-api/).

This plugin focuses on **one thing only**: uploading pre-staged Maven artifacts to the Central Portal and waiting for deployment to complete.
It does **not** handle signing, POM generation, or source/javadoc JAR creation — those are already well-served by Gradle's built-in `maven-publish` and `signing` plugins.

## Why?

- **Minimal** — No external runtime dependencies. Uses Gradle's bundled Jackson 2 for JSON parsing and Java standard library for HTTP and ZIP handling.
- **Central Portal native** — Directly uses the [Publisher API](https://central.sonatype.org/publish/publish-portal-api/), not the legacy OSSRH/Nexus staging API.
- **Atomic multi-module publishing** — Aggregates all subproject artifacts into a single deployment bundle, ensuring all modules are published together or not at all.

## Requirements

- Java 17+
- Gradle 9.0+
- `maven-publish` plugin — applied to each subproject that produces publishable artifacts
- `signing` plugin — applied to each subproject to sign artifacts with GPG (required by Maven Central)

## Quick start

**settings.gradle.kts**

```kotlin
pluginManagement {
    includeBuild("maven-central-publish-plugin") // adjust the path
}
```

**build.gradle.kts** (root project)

```kotlin
plugins {
    id("net.sharplab.maven-central-publish")
}

mavenCentralPublish {
    targetProjects = subprojects.filter { it.name.startsWith("my-library-") }
    username = providers.environmentVariable("MAVEN_CENTRAL_USER")
    password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD")
}
```

```bash
./gradlew publishToCentralPortal
```

## How it works

1. **Configure** — The plugin reads `targetProjects` after the build script is evaluated. For each target project that has the `maven-publish` plugin applied, it adds a `mavenCentralStaging` Maven repository and sets up task dependencies automatically.
2. **Stage** — When `publishToCentralPortal` runs, it first triggers each subproject's `publishAllPublicationsToMavenCentralStagingRepository` task (via `dependsOn`), which stages signed artifacts to `build/maven-central-publish-staging/`.
3. **Bundle** — Gathers files from all staging directories into a single ZIP in Maven repository layout.
4. **Upload & wait** — Uploads the bundle to Central Portal, then polls until `PUBLISHED` or `FAILED`.

## Multi-module project setup

In a multi-module project, you typically have subprojects that should be published to Maven Central and others that should not (test utilities, integration tests, etc.).

The `targetProjects` property controls which subprojects are included. The plugin only configures subprojects that have the `maven-publish` plugin applied — if a project in the list does not have `maven-publish`, it is silently skipped.

### Full example

Consider a project with this structure:

```
my-project/
├── my-library-core/          # publish to Maven Central
├── my-library-extra/         # publish to Maven Central
├── my-library-test-utils/    # NOT published (internal test helper)
├── integration-tests/        # NOT published
└── build.gradle.kts
```

**build.gradle.kts** (root project)

```kotlin
plugins {
    id("net.sharplab.maven-central-publish")
}

// Define which subprojects are published to Maven Central
val publishedSubprojects = subprojects.filter { it.name.startsWith("my-library-") }

// Configure maven-publish and signing for published subprojects
configure(publishedSubprojects) {
    apply(plugin = "java-library")
    apply(plugin = "maven-publish")
    apply(plugin = "signing")

    java {
        withSourcesJar()
        withJavadocJar()
    }

    publishing {
        publications {
            create<MavenPublication>("standard") {
                from(components["java"])
                pom {
                    // ... name, description, license, developers, scm ...
                }
            }
        }
        // No need to define a staging repository — the plugin adds one automatically
    }

    signing {
        useInMemoryPgpKeys(/* ... */)
        sign(publishing.publications["standard"])
    }
}

// Register published subprojects with the plugin
mavenCentralPublish {
    targetProjects = publishedSubprojects
    username = providers.environmentVariable("MAVEN_CENTRAL_USER")
    password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD")
}
```

With this setup:
- `my-library-core` and `my-library-extra` have `maven-publish` + `signing` applied, so they are included in the deployment bundle
- `my-library-test-utils` also matches the filter but does NOT have `maven-publish` applied, so it is skipped
- `integration-tests` does not match the filter at all
- Running `./gradlew publishToCentralPortal` stages all published subprojects, bundles them into one ZIP, and uploads atomically

### Single-module projects

For a single-module project, pass the root project itself:

```kotlin
plugins {
    id("java-library")
    id("maven-publish")
    id("signing")
    id("net.sharplab.maven-central-publish")
}

mavenCentralPublish {
    targetProjects = listOf(project)
    username = providers.environmentVariable("MAVEN_CENTRAL_USER")
    password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD")
}
```

## Credentials

The `username` and `password` properties are `Property<String>` with no default value. The consuming build script is responsible for providing them. Common approaches:

**From environment variables:**

```kotlin
mavenCentralPublish {
    username = providers.environmentVariable("MAVEN_CENTRAL_USER")
    password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD")
}
```

**From Gradle properties** (`~/.gradle/gradle.properties` or `-P` flag):

```kotlin
mavenCentralPublish {
    username = providers.gradleProperty("mavenCentralUsername")
    password = providers.gradleProperty("mavenCentralPassword")
}
```

> **Note:** These are the [user tokens](https://central.sonatype.org/publish/generate-portal-token/) generated from your Central Portal account, not your login credentials.

## Configuration reference

```kotlin
mavenCentralPublish {
    // Projects to publish (required)
    // The plugin automatically adds staging repositories and task dependencies
    targetProjects = subprojects.filter { /* ... */ }

    // Credentials (required)
    username = providers.environmentVariable("MAVEN_CENTRAL_USER")
    password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD")

    // AUTOMATIC: publish immediately after validation passes
    // USER_MANAGED: stop at VALIDATED state, require manual publish via Central Portal UI
    publishingType = "AUTOMATIC"  // default

    // Status polling configuration
    retryDelay = 10    // seconds between polls (default)
    maxRetries = 1000  // maximum poll attempts (default)

    // Deployment name shown in Central Portal UI
    deploymentName = "${project.group}:${project.name}:${project.version}"  // default

    // API base URL (override for testing)
    apiBaseUrl = "https://central.sonatype.com/api/v1/publisher"  // default
}
```

## CI/CD example (GitHub Actions)

```yaml
- name: Publish to Maven Central
  env:
    MAVEN_CENTRAL_USER: ${{ secrets.MAVEN_CENTRAL_USER }}
    MAVEN_CENTRAL_PASSWORD: ${{ secrets.MAVEN_CENTRAL_PASSWORD }}
    PGP_SIGNING_KEY: ${{ secrets.PGP_SIGNING_KEY }}
    PGP_SIGNING_KEY_PASSPHRASE: ${{ secrets.PGP_SIGNING_KEY_PASSPHRASE }}
  run: |
    ./gradlew publishToCentralPortal
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for internal design details.

## License

Apache License, Version 2.0
