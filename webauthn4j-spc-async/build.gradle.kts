description = "WebAuthn4J Secure Payment Confirmation Async library"

dependencies {
    // API
    api(project(":webauthn4j-spc"))
    api(project(":webauthn4j-core-async"))

    // Implementation
    implementation(libs.slf4j.api)

    // CompileOnly
    compileOnly(libs.jetbrains.annotations)

    // Test
    testImplementation(platform(libs.spring.boot.bom))
    testImplementation(project(":webauthn4j-test"))
    testImplementation("ch.qos.logback:logback-classic")
    testImplementation("org.assertj:assertj-core")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testCompileOnly(libs.jetbrains.annotations)
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
