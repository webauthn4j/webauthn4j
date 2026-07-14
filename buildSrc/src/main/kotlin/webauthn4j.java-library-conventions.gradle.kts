import com.webauthn4j.gradle.BuildUtils
import java.net.URI

plugins {
    id("webauthn4j.java-conventions")
    id("signing")
    id("maven-publish")
}

val isSnapshot: Boolean = (findProperty("isSnapshot") as? String)?.toBoolean() ?: true

val githubUrl = "https://github.com/webauthn4j/webauthn4j"
val mavenCentralUser = BuildUtils.getVariable(project, "MAVEN_CENTRAL_USER", "mavenCentralUser")
val mavenCentralPassword = BuildUtils.getVariable(project, "MAVEN_CENTRAL_PASSWORD", "mavenCentralPassword")
val pgpSigningKey = BuildUtils.getVariable(project, "PGP_SIGNING_KEY", "pgpSigningKey")
val pgpSigningKeyPassphrase = BuildUtils.getVariable(project, "PGP_SIGNING_KEY_PASSPHRASE", "pgpSigningKeyPassphrase")

publishing {
    publications {
        create<MavenPublication>("standard") {
            from(components["java"])

            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }

            pom {
                name = project.name
                description.set(provider { project.description })
                url = githubUrl
                licenses {
                    license {
                        name = "The Apache Software License, Version 2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                        distribution = "repo"
                    }
                }
                developers {
                    developer {
                        id = "ynojima"
                        name = "Yoshikazu Nojima"
                        email = "mail@ynojima.net"
                    }
                }
                scm {
                    url = githubUrl
                }
            }
        }
    }

    repositories {
        maven {
            name = "snapshot"
            url = URI("https://central.sonatype.com/repository/maven-snapshots/")
            credentials {
                username = mavenCentralUser
                password = mavenCentralPassword
            }
        }
    }
}

signing {
    useInMemoryPgpKeys(pgpSigningKey, pgpSigningKeyPassphrase)
    sign(publishing.publications["standard"])
}

tasks.withType(Sign::class.java).configureEach {
    onlyIf { pgpSigningKey != null && pgpSigningKeyPassphrase != null }
}

tasks.named("publishStandardPublicationToSnapshotRepository") {
    onlyIf { isSnapshot }
}
