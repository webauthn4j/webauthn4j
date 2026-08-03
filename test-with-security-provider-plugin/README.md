# test-with-security-provider Plugin

A Gradle plugin that configures JCA security providers for test execution, enabling tests to run under different security provider configurations (e.g., BouncyCastle, BouncyCastle FIPS).

## How It Works

The plugin combines two mechanisms to reconfigure JCA security providers for test JVMs:

1. **`java.security.properties`** (provider registration) — A dynamically generated properties file registers the desired providers. The JVM loads and instantiates them at startup, avoiding JPMS access restrictions that would occur with reflective instantiation.

2. **Java agent `premain`** (provider removal) — A Java agent runs before the test application starts and removes any providers not in the configured list via `Security.removeProvider()`.

This two-step approach is necessary because:
- Adding providers requires the JVM to instantiate provider classes (some of which are in restricted JDK modules), which only `java.security.properties` can do safely.
- Removing providers requires programmatic access, which only the agent can do before any test class loading occurs.

The plugin jar itself serves as the Java agent (it contains the `Premain-Class` manifest entry).

## Usage

### 1. Include the plugin

In `settings.gradle.kts`:

```kotlin
pluginManagement {
    includeBuild("test-with-security-provider-plugin")
}
```

### 2. Apply the plugin and configure

In your module's `build.gradle.kts`:

```kotlin
plugins {
    id("com.webauthn4j.test-with-security-provider")
}

// Register test suites (via JVM Test Suite Plugin or plain Test tasks)
testing {
    suites {
        register<JvmTestSuite>("testWithBouncyCastle") {
            targets {
                all {
                    testTask.configure {
                        testClassesDirs = sourceSets["test"].output.classesDirs
                        classpath = sourceSets["test"].runtimeClasspath
                    }
                }
            }
        }
    }
}

// Configure security providers for the test suites
testWithSecurityProvider {
    configurations {
        register("testWithBouncyCastle") {
            // Provider class names in priority order
            providers.set(listOf(
                "org.bouncycastle.jce.provider.BouncyCastleProvider",
                "sun.security.provider.Sun"
            ))
        }
    }
}
```

The configuration name must match the test task name.

### 3. Additional security properties

Use `securityProperties` to set Java security properties (e.g., `securerandom.strongAlgorithms`):

```kotlin
register("testWithBouncyCastleFIPS") {
    providers.set(listOf(
        "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider",
        "org.bouncycastle.entropy.provider.BouncyCastleEntropyProvider"
    ))
    securityProperties.put("securerandom.strongAlgorithms", "ENTROPY:BCRNG")
}
```

Security properties are passed to the test JVM as system properties with the `webauthn4j.test.security.` prefix and applied by the agent via `Security.setProperty()`.

## Architecture

```
Gradle build phase                    Test JVM startup
┌──────────────────────┐              ┌─────────────────────────────────┐
│ Plugin apply:        │              │ 1. JVM starts                   │
│                      │              │                                 │
│ 1. Create extension  │              │ 2. java.security.properties     │
│ 2. Generate .security│── file ──→   │    registers desired providers  │
│    file              │              │    (JVM instantiates them)      │
│ 3. Configure test    │              │                                 │
│    task:             │              │ 3. Agent premain runs:          │
│    - -javaagent      │── jvmArg ──→ │    - Removes unwanted providers │
│    - system props    │── props ──→  │    - Sets security properties   │
│                      │              │                                 │
│                      │              │ 4. Tests execute                │
└──────────────────────┘              └─────────────────────────────────┘
```
