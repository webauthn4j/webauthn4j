import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("webauthn4j.java-conventions")
    alias(libs.plugins.kotlin.jvm)
}

description = "WebAuthn4J FIDO Integration Tests in BDD style"

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // WebAuthn4J (local project)
    testImplementation(project(":webauthn4j-core"))
    testImplementation(project(":webauthn4j-test"))

    // WebAuthn4J CTAP (from Maven Central)
    testImplementation(libs.webauthn4j.ctap.authenticator)
    testImplementation(libs.webauthn4j.ctap.client)

    // Kotlin Coroutines
    testImplementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.kotlinx.coroutines.test)

    // Kotest
    testImplementation(libs.kotest.runner.junit5)
    testImplementation(libs.kotest.assertions.core)
    testImplementation(libs.kotest.framework.datatest)
    // Jackson (for ObjectConverter)
    testImplementation(libs.jackson.databind)
    testImplementation(libs.jackson.dataformat.cbor)
    testImplementation(libs.jackson.module.kotlin)

    // Logging
    testImplementation(platform(libs.spring.boot.bom))
    testImplementation("ch.qos.logback:logback-classic")
}

sonarqube {
    isSkipProject = true
}
