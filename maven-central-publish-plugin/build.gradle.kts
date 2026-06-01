plugins {
    `kotlin-dsl`
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("com.fasterxml.jackson.core:jackson-databind:2.18.6")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:2.18.6")

    testImplementation("org.junit.jupiter:junit-jupiter:5.12.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
}

tasks.test {
    useJUnitPlatform()
}

// Make compileOnly dependencies (e.g. jackson-databind provided by Gradle at runtime)
// available in Gradle TestKit's plugin classpath.
tasks.pluginUnderTestMetadata {
    pluginClasspath.from(configurations.compileClasspath)
}


gradlePlugin {
    plugins {
        register("mavenCentralPublish") {
            id = "net.sharplab.maven-central-publish"
            implementationClass = "net.sharplab.gradle.mavencentral.MavenCentralPublishPlugin"
        }
    }
}
