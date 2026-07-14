import com.webauthn4j.gradle.VersionUtils
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.external.javadoc.StandardJavadocDocletOptions

plugins {
    id("java-library")
    id("jacoco")
}

val webAuthn4JVersion: String by project
val isSnapshot: Boolean = (findProperty("isSnapshot") as? String)?.toBoolean() ?: true

group = "com.webauthn4j"
version = VersionUtils.getEffectiveVersion(isSnapshot, webAuthn4JVersion)

repositories {
    mavenCentral()
}

java {
    // Use sourceCompatibility/targetCompatibility instead of options.release so that
    // APIs introduced after JDK 17 (e.g. ML-DSA in JDK 24) remain accessible at compile
    // time. --release would restrict the API surface to JDK 17. Users who call those newer
    // APIs must run on a JDK that provides them.
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17

    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("-Xlint:-module")
    options.compilerArgs.add("-Werror")
}

// Ensure reproducible builds: deterministic file order and fixed timestamps in archives.
// This is the default since Gradle 9.0, but stated explicitly for clarity and to prevent
// accidental regression if defaults change.
tasks.withType<AbstractArchiveTask>().configureEach {
    isReproducibleFileOrder = true
    isPreserveFileTimestamps = false
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showExceptions = true
        exceptionFormat = TestExceptionFormat.FULL
        showCauses = true
        showStackTraces = true
        showStandardStreams = false
    }
}

tasks.javadoc {
    (options as StandardJavadocDocletOptions).apply {
        charset("UTF-8")
        encoding("UTF-8")
        addStringOption("Xdoclint:all,-missing", "-quiet")
    }
}

tasks.jacocoTestReport {
    reports {
        xml.required = true
    }
}
