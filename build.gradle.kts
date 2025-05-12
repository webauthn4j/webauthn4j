import org.asciidoctor.gradle.jvm.AsciidoctorTask
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.jvm.tasks.Jar
import org.jreleaser.model.Active
import java.net.URI
import java.nio.charset.StandardCharsets

plugins {
    id("java-library")
    id("signing")
    id("maven-publish")
    id("jacoco")

    id(libs.plugins.jreleaser.get().pluginId) version libs.versions.jreleaser
    id(libs.plugins.asciidoctor.get().pluginId) version libs.versions.asciidoctor
    id(libs.plugins.sonarqube.get().pluginId) version libs.versions.sonarqube
}

private val webAuthn4JVersion: String by project
private val isSnapshot: Boolean = (findProperty("isSnapshot") as? String)?.toBoolean() ?: true
private val effectiveVersion = getEffectiveVersion()

allprojects {
    group = "com.webauthn4j"
    version = effectiveVersion

    repositories {
        mavenCentral()
        maven(url = "https://jitpack.io")
    }
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "signing")
    apply(plugin = "maven-publish")
    apply(plugin = "jacoco")
    apply(plugin = "org.jreleaser")

    java {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11 // Although webauthn4j uses JDK 15+ API to support EdDSA, keep target version 11 to support JDK11 users who don't need EdDSA.
    }

    tasks.test {
        useJUnitPlatform()
        testLogging {
            events("passed", "skipped", "failed") //, "standardOut", "standardError"
            showExceptions = true
            exceptionFormat = TestExceptionFormat.FULL
            showCauses = true
            showStackTraces = true

            showStandardStreams = false
        }
    }

    tasks.javadoc{
        options {
            charset("UTF-8")
            encoding("UTF-8")
        }
    }

    tasks.register<Jar>("javadocJar") {
        group = "build"
        description = "Assembles Javadoc jar"
        dependsOn(tasks.named("javadoc"))
        archiveClassifier = "javadoc"
        from(tasks.named<Javadoc>("javadoc").get().destinationDir)
    }

    tasks.register<Jar>("sourcesJar") {
        group = "build"
        description = "Assembles sources jar"
        archiveClassifier = "sources"
        from(sourceSets.main.get().allSource)
    }

    tasks.jacocoTestReport {
        reports {
            xml.required = true
        }
    }

    fun getVariable(envName: String, propertyName: String): String?{
        return if (System.getenv(envName) != null && System.getenv(envName).isNotEmpty()) {
            System.getenv(envName)
        } else if (project.hasProperty(propertyName)) {
            project.property(propertyName) as String?
        } else {
            null
        }
    }

    val githubUrl = "https://github.com/webauthn4j/webauthn4j"
    val mavenCentralUser = getVariable("MAVEN_CENTRAL_USER", "mavenCentralUser")
    val mavenCentralPassword = getVariable("MAVEN_CENTRAL_PASSWORD", "mavenCentralPassword")
    val pgpSigningKey = getVariable("PGP_SIGNING_KEY", "pgpSigningKey")
    val pgpSigningKeyPassphrase = getVariable("PGP_SIGNING_KEY_PASSPHRASE", "pgpSigningKeyPassphrase")

    publishing {
        publications{
            create<MavenPublication>("standard") {
                from(components["java"])
                artifact(tasks.named("sourcesJar"))
                artifact(tasks.named("javadocJar"))

                // "Resolved versions" strategy is used to define dependency version because WebAuthn4J use dependencyManagement (BOM) feature
                // to define its dependency versions. Without "Resolved versions" strategy, version will not be exposed
                // to dependencies.dependency.version in POM file, and it cause warning in the library consumer environment.
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
                    //description = project.description.toString() //TODO: this doesn't work. to be fixed. https://github.com/gradle/gradle/issues/12259
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
                pom.withXml{
                    asNode().appendNode("description", project.description) // workaround for https://github.com/gradle/gradle/issues/12259
                }
            }
        }

        repositories {
            maven {
                name = "localStaging"
                url = layout.buildDirectory.dir("local-staging").get().asFile.toURI()
            }
            maven {
                name = "snapshot"
                url = URI("https://central.sonatype.com/repository/maven-snapshots/")
                credentials {
                    username = mavenCentralUser
                    password = mavenCentralPassword
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

        jreleaser {
            project {
                authors.set(listOf("Yoshikazu Nojima"))
                license = "Apache-2.0"
                links {
                    homepage = githubUrl
                }
                version = effectiveVersion
            }

            release{
                github{
                    token.set("dummy")
                    skipRelease = true
                    skipTag = true
                }
            }

            deploy {
                maven {
                    mavenCentral {
                        this.register("mavenCentral"){
                            active = Active.RELEASE
                            sign = false // artifacts are signed by gradle native feature. signing by jreleaser is not required.
                            username = mavenCentralUser
                            password = mavenCentralPassword
                            url = "https://central.sonatype.com/api/v1/publisher/"
                            stagingRepository(layout.buildDirectory.dir("local-staging").get().asFile.absolutePath)
                            retryDelay = 10
                            maxRetries = 1000
                        }
                    }
                }
            }
        }
    }
}

tasks.register("bumpPatchVersion"){
    group = "documentation"

    doLast{
        val regex = Regex("""^webAuthn4JVersion=.*$""", RegexOption.MULTILINE)
        val bumpedVersion = bumpPatchVersion(webAuthn4JVersion)
        val replacement = "webAuthn4JVersion=${bumpedVersion}"

        val file = file("gradle.properties")
        val original = file.readText(StandardCharsets.UTF_8)
        if (!regex.containsMatchIn(original)) {
            throw GradleException("webAuthn4JVersion property not found in gradle.properties")
        }
        val updated = original.replaceFirst(regex, replacement)
        file.writeText(updated, StandardCharsets.UTF_8)
    }
}

tasks.register("updateVersionsInDocuments"){
    group = "documentation"
    description = "Update versions in document source code"

    doLast {
        val regex = Regex("""<webauthn4j\.version>.*</webauthn4j\.version>""")
        val replacement = "<webauthn4j.version>$effectiveVersion</webauthn4j.version>"

        val files = arrayOf(file("README.md"), file("docs/src/reference/asciidoc/en/introduction.adoc"), file("docs/src/reference/asciidoc/ja/introduction.adoc"), file("docs/src/reference/asciidoc/en/quick-start.adoc"), file("docs/src/reference/asciidoc/ja/quick-start.adoc"))
        files.forEach { file ->
            val updated = file.readText(StandardCharsets.UTF_8).replaceFirst(regex, replacement)
            file.writeText(updated, StandardCharsets.UTF_8)
        }
    }
}

tasks.register("switchToSnapshot"){
    group = "documentation"

    doLast{
        val regex = Regex("""^isSnapshot=.*$""", RegexOption.MULTILINE)
        val replacement = "isSnapshot=true"

        val file = file("gradle.properties")
        val original = file.readText(StandardCharsets.UTF_8)
        if (!regex.containsMatchIn(original)) {
            throw GradleException("isSnapshot property not found in gradle.properties")
        }
        val updated = original.replaceFirst(regex, replacement)
        file.writeText(updated, StandardCharsets.UTF_8)
    }
}

tasks.register("switchToRelease"){
    group = "documentation"

    doLast{
        val regex = Regex("""^isSnapshot=.*$""", RegexOption.MULTILINE)
        val replacement = "isSnapshot=false"

        val file = file("gradle.properties")
        val original = file.readText(StandardCharsets.UTF_8)
        if (!regex.containsMatchIn(original)) {
            throw GradleException("isSnapshot property not found in gradle.properties")
        }
        val updated = original.replaceFirst(regex, replacement)
        file.writeText(updated, StandardCharsets.UTF_8)
    }
}


tasks.register<JavaExec>("generateReleaseNote") {
    group = "documentation"
    description = "Generate release note"

    classpath = files("gradle/lib/github-release-notes-generator.jar")

    args(webAuthn4JVersion, file("build/release-note.md").absolutePath, "--spring.config.location=file:" + file("github-release-notes-generator.yml").absolutePath)
}

asciidoctorj{
    modules{
        diagram.use()
        diagram.version("2.3.1")
    }
    attributes(mapOf("source-highlighter" to "rouge"))
}

tasks.register<AsciidoctorTask>("generateReferenceJA") {
    group = "documentation"
    description = "Generate reference (ja)"

    baseDirFollowsSourceDir()
    setSourceDir(file("docs/src/reference/asciidoc/ja"))
    setOutputDir(file("build/docs/asciidoc/html5/ja"))
    options(mapOf("eruby" to "erubis"))
    //noinspection GroovyAssignabilityCheck
    attributes(mapOf(
        "docinfo" to "",
        "copycss" to "",
        "icons" to "font",
        "source-highlighter" to "prettify",
        "sectanchors" to "",
        "toc2" to "",
        "idprefix" to "",
        "idseparator" to "-",
        "doctype" to "book",
        "numbered" to "",
        "revnumber" to webAuthn4JVersion
    ))
}

tasks.register<AsciidoctorTask>("generateReferenceEN") {
    group = "documentation"
    description = "Generate reference (en)"

    baseDirFollowsSourceDir()
    setSourceDir(file("docs/src/reference/asciidoc/en"))
    setOutputDir(file("build/docs/asciidoc/html5/en"))
    options(mapOf("eruby" to "erubis"))
    //noinspection GroovyAssignabilityCheck
    attributes(mapOf(
        "docinfo" to "",
        "copycss" to "",
        "icons" to "font",
        "source-highlighter" to "prettify",
        "sectanchors" to "",
        "toc2" to "",
        "idprefix" to "",
        "idseparator" to "-",
        "doctype" to "book",
        "numbered" to "",
        "revnumber" to webAuthn4JVersion
    ))
}

sonarqube {
    properties {
        property("sonar.projectKey", "webauthn4j")
        property("sonar.issue.ignore.multicriteria", "e1,e2,e3,e4")
        property("sonar.issue.ignore.multicriteria.e1.ruleKey", "java:S110")
        property("sonar.issue.ignore.multicriteria.e1.resourceKey", "**/*.java")
        property("sonar.issue.ignore.multicriteria.e2.ruleKey", "java:S1452")
        property("sonar.issue.ignore.multicriteria.e2.resourceKey", "**/*.java")
        property("sonar.issue.ignore.multicriteria.e3.ruleKey", "common-java:DuplicatedBlocks")
        property("sonar.issue.ignore.multicriteria.e3.resourceKey", "**/*.java")
        property("sonar.issue.ignore.multicriteria.e4.ruleKey", "java:S5778")
        property("sonar.issue.ignore.multicriteria.e4.resourceKey", "**/*.java")
    }
}

private fun getEffectiveVersion(): String{
    return when {
        isSnapshot -> webAuthn4JVersion.plus("-SNAPSHOT")
        else -> webAuthn4JVersion.plus(".RELEASE")
    }
}

private fun bumpPatchVersion(version: String): String {
    val parts = version.split(".")
    require(parts.size == 3) { "Version must be in the format 'X.Y.Z': $version" }

    val major = parts[0].toInt()
    val minor = parts[1].toInt()
    val patch = parts[2].toInt() + 1

    return "$major.$minor.$patch"
}
