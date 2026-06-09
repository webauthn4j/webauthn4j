plugins {
    `kotlin-dsl`
}

repositories {
    mavenCentral()
}

gradlePlugin {
    plugins {
        register("toolchainPinning") {
            id = "com.webauthn4j.toolchain-pinning"
            implementationClass = "com.webauthn4j.gradle.toolchain.ToolchainPinningPlugin"
        }
    }
}
