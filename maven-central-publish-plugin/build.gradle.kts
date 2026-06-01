plugins {
    `kotlin-dsl`
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("tools.jackson.core:jackson-databind:3.1.3")

    testImplementation("org.junit.jupiter:junit-jupiter:5.12.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
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
