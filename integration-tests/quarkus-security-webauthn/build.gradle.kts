plugins {
    id("java")
    alias(libs.plugins.quarkus)
}

dependencies {
    implementation(platform(libs.quarkus.bom))
    
    implementation("io.quarkus:quarkus-security-webauthn") {
        exclude(group = "com.webauthn4j")
    }
    implementation("io.quarkus:quarkus-jdbc-postgresql")
    implementation("io.quarkus:quarkus-rest")
    implementation("io.quarkus:quarkus-rest-jackson")
    implementation("io.quarkus:quarkus-hibernate-orm-panache")
    implementation("io.quarkus:quarkus-jdbc-h2")

    // Local WebAuthn4J modules
    implementation(project(":webauthn4j-core"))
    implementation(project(":webauthn4j-core-async"))
    implementation(project(":webauthn4j-metadata-async"))

    testImplementation("io.quarkus:quarkus-junit5")
    testImplementation("io.rest-assured:rest-assured")
    testImplementation(libs.assertj.core)

    // Playwright for E2E UI tests + logger API
    testImplementation(libs.playwright)
    testImplementation(libs.slf4j.api)
}

tasks.withType<Test> {
    systemProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager")
}

sonarqube {
    isSkipProject = true
}
