plugins {
    id("java")
    alias(libs.plugins.quarkus)
}

description = "WebAuthn4J Integration Test for Secure Payment Confirmation"

dependencies {
    implementation(platform(libs.quarkus.bom))

    implementation("io.quarkus:quarkus-rest")
    implementation("io.quarkus:quarkus-rest-jackson")

    implementation(project(":webauthn4j-spc"))
    compileOnly(libs.jetbrains.annotations)

    testImplementation("io.quarkus:quarkus-junit5")
    testImplementation(libs.assertj.core)
    testImplementation(libs.slf4j.api)

    // Selenium WebDriver is used instead of Playwright because the SPC spec (§10.1)
    // defines test automation via a WebDriver extension command
    // (POST /session/{id}/secure-payment-confirmation/set-mode).
    // This command is not available in the Chrome DevTools Protocol (CDP),
    // which Playwright uses. Selenium + ChromeDriver supports WebDriver
    // extension commands natively.
    testImplementation("org.seleniumhq.selenium:selenium-java:4.33.0")
    testImplementation("org.seleniumhq.selenium:selenium-chromium-driver:4.33.0")
}

tasks.withType<Test> {
    systemProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager")
}

sonarqube {
    isSkipProject = true
}
