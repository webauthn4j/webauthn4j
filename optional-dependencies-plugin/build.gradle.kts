plugins {
    `kotlin-dsl`
}

repositories {
    mavenCentral()
}

gradlePlugin {
    plugins {
        register("optionalDependencies") {
            id = "com.webauthn4j.optional-dependencies"
            implementationClass = "com.webauthn4j.gradle.OptionalDependenciesPlugin"
        }
    }
}
