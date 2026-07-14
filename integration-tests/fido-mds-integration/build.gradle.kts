plugins {
    id("webauthn4j.java-conventions")
}

description = "WebAuthn4J FIDO MDS Integration Tests"

dependencies {
    testImplementation(project(":webauthn4j-metadata"))
    testImplementation(project(":webauthn4j-metadata-async"))

    testImplementation(platform(libs.spring.boot.bom))
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(libs.assertj.core)
    testImplementation("org.mockito:mockito-core")
}

sonarqube {
    isSkipProject = true
}
