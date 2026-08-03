plugins {
    `kotlin-dsl`
    `java-library`
}

repositories {
    mavenCentral()
}

gradlePlugin {
    plugins {
        register("testWithSecurityProvider") {
            id = "com.webauthn4j.test-with-security-provider"
            implementationClass = "com.webauthn4j.gradle.TestWithSecurityProviderPlugin"
        }
    }
}

tasks.jar {
    manifest {
        attributes("Premain-Class" to "com.webauthn4j.gradle.agent.SecurityProviderAgent")
    }
}
