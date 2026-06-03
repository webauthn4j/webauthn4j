plugins {
    `kotlin-dsl`
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.jackson.databind)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(libs.assertj.core)
    testImplementation(libs.mockwebserver)
}

tasks.test {
    useJUnitPlatform()
}


gradlePlugin {
    plugins {
        register("mavenCentralPublish") {
            id = "net.sharplab.maven-central-publish"
            implementationClass = "net.sharplab.gradle.mavencentral.MavenCentralPublishPlugin"
        }
    }
}
