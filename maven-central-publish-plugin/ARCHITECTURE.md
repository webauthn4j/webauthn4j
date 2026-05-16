# Architecture

## Overview

This plugin uploads locally staged Maven artifacts to Maven Central via the [Sonatype Central Portal Publisher API](https://central.sonatype.org/publish/publish-portal-api/).

Signing, POM generation, and source/javadoc JAR creation are out of scope — those are handled by Gradle's built-in `maven-publish` and `signing` plugins. This plugin is responsible for:

- Automatically configuring staging repositories on target subprojects
- Bundling staged artifacts into a single ZIP
- Uploading the bundle to Central Portal and waiting for deployment to complete

### Prerequisites

This plugin requires the following Gradle plugins to be applied to each target subproject:

- **`maven-publish`** — Defines publications (artifacts and POM metadata) and outputs them to the staging repository. The plugin waits for `maven-publish` to be applied via `pluginManager.withPlugin` and silently skips subprojects without it.
- **`signing`** — Signs artifacts with GPG. Required by Maven Central.

## Processing flow

```
┌─────────────────────────────────────────────────────────────────┐
│  Gradle build (root project)                                    │
│                                                                 │
│  mavenCentralPublish {                                          │
│      targetProjects = publishedSubprojects                      │
│  }                                                              │
│    │                                                            │
│    │  After evaluation, the plugin automatically:               │
│    │  - Adds mavenCentralStaging repository to each subproject  │
│    │  - Configures publishToCentralPortal dependsOn             │
│    │                                                            │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐                   │
│  │ module-a  │  │ module-b  │  │ module-c  │  ...               │
│  │           │  │           │  │           │                    │
│  │ maven-    │  │ maven-    │  │ maven-    │                    │
│  │ publish   │  │ publish   │  │ publish   │                    │
│  │ + signing │  │ + signing │  │ + signing │                    │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘                   │
│        │              │              │                          │
│        ▼              ▼              ▼                          │
│   build/maven-   build/maven-   build/maven-                    │
│   central-       central-       central-                        │
│   publish-       publish-       publish-                        │
│   staging/       staging/       staging/                        │
│        │              │              │                          │
│        └──────────────┼──────────────┘                          │
│                       │                                         │
│                       ▼                                         │
│  ┌─────────────────────────────────────────────────────┐        │
│  │  PublishToCentralPortalTask (publishToCentralPortal) │        │
│  │                                                     │        │
│  │  1. Collect files from all staging directories      │        │
│  │  2. Create a single ZIP bundle                      │        │
│  │  3. Upload to Central Portal API                    │        │
│  │  4. Poll status until PUBLISHED                     │        │
│  └─────────────────────────────────────────────────────┘        │
│                       │                                         │
└───────────────────────┼─────────────────────────────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │  Central Portal   │
              │  Publisher API    │
              │                   │
              │  POST /upload     │
              │  POST /status     │
              └───────────────────┘
```

All module artifacts are bundled into a single ZIP and uploaded as one deployment. This provides **atomic publishing** — all modules are published together or not at all.

## Project structure

```
maven-central-publish-plugin/
├── build.gradle.kts
├── settings.gradle.kts
├── README.md
├── ARCHITECTURE.md
└── src/
    ├── main/kotlin/net/sharplab/gradle/mavencentral/
    │   ├── MavenCentralPublishPlugin.kt      # Plugin entry point
    │   ├── MavenCentralPublishExtension.kt   # DSL configuration (properties only)
    │   ├── PublishToCentralPortalTask.kt     # Gradle task
    │   ├── BundleCreator.kt                  # ZIP bundle creation
    │   ├── DeploymentFailedException.kt      # FAILED state exception
    │   ├── DeploymentTimeoutException.kt     # Polling timeout exception
    │   └── client/                           # API client layer (no Gradle dependency)
    │       ├── CentralPortalClient.kt        # HTTP communication
    │       ├── DeploymentStatus.kt           # API response data class
    │       └── CentralPortalApiException.kt  # API error exception
    └── test/kotlin/net/sharplab/gradle/mavencentral/
        ├── MavenCentralPublishPluginTest.kt  # Gradle TestKit tests
        ├── BundleCreatorTest.kt              # ZIP creation tests
        └── client/
            └── CentralPortalClientTest.kt    # MockWebServer tests
```

### Package design

```
net.sharplab.gradle.mavencentral              Gradle plugin layer
├── MavenCentralPublishPlugin                 Plugin<Project>
├── MavenCentralPublishExtension              DSL properties (targetProjects, credentials, etc.)
├── PublishToCentralPortalTask                Gradle task
├── BundleCreator                             ZIP bundle creation utility
├── DeploymentFailedException                 Thrown when deployment reaches FAILED
└── DeploymentTimeoutException                Thrown when polling exceeds maxRetries

net.sharplab.gradle.mavencentral.client       API client layer (no Gradle dependency)
├── CentralPortalClient                       HTTP communication only
├── DeploymentStatus                          API response data class
└── CentralPortalApiException                 API error exception
```

The `client` package has no dependency on Gradle APIs, making it independently usable and testable outside of Gradle.

## Components

### MavenCentralPublishPlugin

Plugin entry point. Implements `Plugin<Project>` and performs the following on apply:

1. Creates `MavenCentralPublishExtension` as the `mavenCentralPublish` extension
2. Registers `PublishToCentralPortalTask` as the `publishToCentralPortal` task
3. Wires extension properties to task inputs
4. Sets convention values (defaults) for configurable properties

After the build script is evaluated (`afterEvaluate`), the plugin reads `targetProjects` and for each subproject:

1. Waits for `maven-publish` to be applied (`pluginManager.withPlugin`)
2. Adds a `mavenCentralStaging` Maven repository (path: `build/maven-central-publish-staging/`)
3. Adds the staging directory to the task's `stagingDirectories`
4. Adds `dependsOn` on `publishAllPublicationsToMavenCentralStagingRepository`

### MavenCentralPublishExtension

Declarative DSL interface for user configuration. All members are Gradle `Property` types — no methods with side effects.

| Property | Type | Default | Description |
|---|---|---|---|
| `targetProjects` | `SetProperty<Project>` | empty | Subprojects to publish to Maven Central |
| `username` | `Property<String>` | (none) | Central Portal username |
| `password` | `Property<String>` | (none) | Central Portal password |
| `publishingType` | `Property<String>` | `"AUTOMATIC"` | `AUTOMATIC` or `USER_MANAGED` |
| `retryDelay` | `Property<Int>` | `10` | Seconds between status polls |
| `maxRetries` | `Property<Int>` | `1000` | Maximum number of poll attempts |
| `apiBaseUrl` | `Property<String>` | `https://central.sonatype.com/api/v1/publisher` | API base URL |
| `deploymentName` | `Property<String>` | `$group:$name:$version` | Name shown in Central Portal UI |

Credentials have no default — the consuming build script is responsible for providing them (e.g., via `providers.environmentVariable()` or `providers.gradleProperty()`).

### PublishToCentralPortalTask

Gradle task that performs the actual deployment. Extends `DefaultTask`.

**Task input annotations:**

| Property | Annotation | Rationale |
|---|---|---|
| `stagingDirectories` | `@InputFiles` | Detect file content changes |
| `deploymentName` | `@Input` | Track value changes |
| `publishingType` | `@Input` | Track value changes |
| `username` | `@Internal` | Prevent credential leakage to build cache keys or build scans |
| `password` | `@Internal` | Same as above |
| `retryDelay` | `@Internal` | Polling config does not affect deployment result |
| `maxRetries` | `@Internal` | Same as above |
| `apiBaseUrl` | `@Internal` | Same as above |

`outputs.upToDateWhen { false }` ensures the task always runs, since deployment is a non-idempotent side effect.

**Execution flow:**

```
publish()
  │
  ├── collectStagingDirectories()
  │     Validate directories exist and contain files
  │
  ├── BundleCreator.createZipBundle(dirs)
  │     Merge all directories into a single ZIP
  │
  ├── CentralPortalClient.upload(zipBytes, name, publishingType)
  │     Upload and receive deployment ID
  │
  └── awaitPublished(client, deploymentId)
        Poll loop (max maxRetries, interval retryDelay seconds):
          │
          ├── PUBLISHED → success, return
          ├── FAILED    → throw DeploymentFailedException
          ├── PENDING / VALIDATING / VALIDATED / PUBLISHING → sleep, continue
          └── unknown   → warn, continue
```

Status changes are logged only when the state transitions, preventing log spam during long polling.

### BundleCreator

Utility object that creates a ZIP deployment bundle from staging directories.

```kotlin
object BundleCreator {
    fun createZipBundle(stagingDirs: List<File>): ByteArray
}
```

Files are added to the ZIP with their relative paths from the staging directory root, preserving the Maven repository layout. The ZIP is created in memory (`ByteArrayOutputStream`).

### CentralPortalClient

HTTP client for the Central Portal Publisher API. Has no Gradle dependency.

**Dependencies:**

| Purpose | Library | Rationale |
|---|---|---|
| HTTP | `java.net.http.HttpClient` | Java 11+ standard library |
| JSON | `com.fasterxml.jackson.databind.ObjectMapper` | Bundled with Gradle runtime; declared as `compileOnly` |

**API interactions:**

| Operation | Method | Endpoint | Response |
|---|---|---|---|
| Upload bundle | `upload()` | `POST /upload?publishingType=...&name=...` | `201` + deployment ID (plain text) |
| Check status | `getStatus()` | `POST /status?id=<deploymentId>` | `200` + JSON with `deploymentState` and `errors` |

Authentication uses `Authorization: Bearer <Base64(username:password)>`.

The multipart/form-data body for upload is constructed manually since `java.net.http.HttpClient` does not provide multipart support.

### Exceptions

| Exception | Package | Thrown by | Description |
|---|---|---|---|
| `CentralPortalApiException` | `client` | `CentralPortalClient` | Unexpected HTTP status or unparseable response |
| `DeploymentFailedException` | (root) | `PublishToCentralPortalTask` | Deployment reached `FAILED` state |
| `DeploymentTimeoutException` | (root) | `PublishToCentralPortalTask` | Polling exceeded `maxRetries` |

## Deployment state machine

```
PENDING ──► VALIDATING ──► VALIDATED ──► PUBLISHING ──► PUBLISHED
                │                                        (terminal)
                │
                └──► FAILED (terminal)
```

| State | Meaning |
|---|---|
| `PENDING` | Upload complete, waiting for validation |
| `VALIDATING` | Validation in progress (POM, signatures, checksums) |
| `VALIDATED` | Validation passed. Stops here if `publishingType=USER_MANAGED` |
| `PUBLISHING` | Syncing to Maven Central |
| `PUBLISHED` | Available on Maven Central |
| `FAILED` | Error occurred. Details in `errors` field |

With `publishingType=AUTOMATIC` (default), `VALIDATED` automatically transitions to `PUBLISHING` → `PUBLISHED`.

## Test structure

### CentralPortalClientTest (MockWebServer)

Unit tests for the `client` package. Uses OkHttp's `MockWebServer` as a local HTTP server to test client logic without making real API calls.

The mock boundary is at the HTTP transport layer — multipart body construction, auth token generation, and JSON parsing all execute as real code.

| Test group | Coverage |
|---|---|
| `UploadTest` | Success, query parameters, auth header, multipart body, HTTP errors |
| `GetStatusTest` | PUBLISHED/PENDING/FAILED JSON parsing, request format, HTTP errors |

### BundleCreatorTest

Unit tests for ZIP bundle creation.

| Test | Coverage |
|---|---|
| Single directory | Files are added with correct relative paths |
| Multiple directories | Files from all directories are merged |
| Empty directory | Produces an empty ZIP |

### MavenCentralPublishPluginTest (Gradle TestKit)

Integration tests using `GradleRunner` to execute real Gradle builds in temporary directories.

| Test group | Coverage |
|---|---|
| `PluginApplicationTest` | Task and extension registration |
| `TargetProjectsTest` | Staging repository auto-added, dependsOn configured, artifacts staged, non-maven-publish projects skipped |
| `PublishToCentralPortalTaskTest` | Error message when credentials are missing |

## Configuration cache compatibility

- **Gradle managed types** (`Property<T>`, `ConfigurableFileCollection`) for all task inputs
- **No `Project` access at execution time** — all values are captured into properties during configuration
- **`CentralPortalClient` created at execution time** — `HttpClient` is not serializable, so it is instantiated inside `@TaskAction`

## Integration as an included build

This plugin is integrated via [Gradle included build](https://docs.gradle.org/current/userguide/composite_builds.html):

```kotlin
// settings.gradle.kts
pluginManagement {
    includeBuild("maven-central-publish-plugin")
}
```

Benefits:
- Plugin source lives in the same repository as the host project
- No need to publish to a plugin registry
- Changes to the plugin are immediately reflected in the host build

Applying the plugin via the `plugins { }` block causes Gradle to generate type-safe extension accessors (`mavenCentralPublish { ... }`).

## Error handling

| Condition | Exception | Source |
|---|---|---|
| No staging directories found | `GradleException` | `PublishToCentralPortalTask` |
| All staging directories empty | `GradleException` | `PublishToCentralPortalTask` |
| Credentials not configured | `MissingValueException` | Gradle `Property.get()` |
| Upload HTTP error (non-201) | `CentralPortalApiException` | `CentralPortalClient.upload()` |
| Status check HTTP error (non-200) | `CentralPortalApiException` | `CentralPortalClient.getStatus()` |
| Deployment state `FAILED` | `DeploymentFailedException` | `PublishToCentralPortalTask` |
| Polling timeout (maxRetries exceeded) | `DeploymentTimeoutException` | `PublishToCentralPortalTask` |
| Network error | `IOException` | `HttpClient.send()` |

## Reference

- [Central Portal Publisher API](https://central.sonatype.org/publish/publish-portal-api/) — Endpoints, authentication, request/response format
- [Generate Portal Token](https://central.sonatype.org/publish/generate-portal-token/) — How to obtain API credentials
- [Upload Requirements](https://central.sonatype.org/publish/publish-portal-upload/) — ZIP bundle format, required files (POM, signatures, checksums)
- [Gradle maven-publish Plugin](https://docs.gradle.org/current/userguide/publishing_maven.html) — Publication definition, repository configuration
- [Gradle signing Plugin](https://docs.gradle.org/current/userguide/signing_plugin.html) — GPG artifact signing
- [Gradle Composite Builds](https://docs.gradle.org/current/userguide/composite_builds.html) — Included build mechanism
