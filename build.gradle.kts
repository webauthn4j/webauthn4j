import com.webauthn4j.gradle.BuildUtils
import com.webauthn4j.gradle.VersionUtils
import org.asciidoctor.gradle.jvm.AsciidoctorTask
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import java.net.URI
import org.gradle.external.javadoc.StandardJavadocDocletOptions
import java.nio.charset.StandardCharsets

plugins {
    id("java-library")
    id("signing")
    id("maven-publish")
    id("jacoco")

    id("net.sharplab.maven-central-publish")
    id(libs.plugins.asciidoctor.get().pluginId) version libs.versions.asciidoctor
    id(libs.plugins.sonarqube.get().pluginId) version libs.versions.sonarqube
}

private val webAuthn4JVersion: String by project
private val isSnapshot: Boolean = (findProperty("isSnapshot") as? String)?.toBoolean() ?: true
private val effectiveVersion = VersionUtils.getEffectiveVersion(isSnapshot, webAuthn4JVersion)

allprojects {
    group = "com.webauthn4j"
    version = effectiveVersion

    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "jacoco")

    java {
        // Use sourceCompatibility/targetCompatibility instead of options.release so that
        // APIs introduced after JDK 17 (e.g. ML-DSA in JDK 24) remain accessible at compile
        // time. --release would restrict the API surface to JDK 17. Users who call those newer
        // APIs must run on a JDK that provides them.
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17

        withSourcesJar()
        withJavadocJar()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.compilerArgs.add("-Xlint:-module") // Suppress 'module not found' warning regarding 'exports to' directive on multi-module projects.
        options.compilerArgs.add("-Werror") // Treat all warnings as errors
    }

    // Ensure reproducible builds: deterministic file order and fixed timestamps in archives.
    // This is the default since Gradle 9.0, but stated explicitly for clarity and to prevent
    // accidental regression if defaults change.
    tasks.withType<AbstractArchiveTask>().configureEach {
        isReproducibleFileOrder = true
        isPreserveFileTimestamps = false
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
        (options as StandardJavadocDocletOptions).apply {
            charset("UTF-8")
            encoding("UTF-8")
            addStringOption("Xdoclint:all,-missing", "-quiet")
        }
    }

    tasks.jacocoTestReport {
        reports {
            xml.required = true
        }
    }

}

configure(subprojects.filter { it.name.startsWith("webauthn4j-") }) {
    apply(plugin = "signing")
    apply(plugin = "maven-publish")

    val githubUrl = "https://github.com/webauthn4j/webauthn4j"
    val mavenCentralUser = BuildUtils.getVariable(project, "MAVEN_CENTRAL_USER", "mavenCentralUser")
    val mavenCentralPassword = BuildUtils.getVariable(project, "MAVEN_CENTRAL_PASSWORD", "mavenCentralPassword")
    val pgpSigningKey = BuildUtils.getVariable(project, "PGP_SIGNING_KEY", "pgpSigningKey")
    val pgpSigningKeyPassphrase = BuildUtils.getVariable(project, "PGP_SIGNING_KEY_PASSPHRASE", "pgpSigningKeyPassphrase")

    publishing {
        publications{
            create<MavenPublication>("standard") {
                from(components["java"])

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
                    description.set(provider { project.description }) // use provider for lazy initialization
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

    }
}

tasks.register("bumpPatchVersion"){
    group = "documentation"

    doLast{
        val regex = Regex("""^webAuthn4JVersion=.*$""", RegexOption.MULTILINE)
        val bumpedVersion = VersionUtils.bumpPatchVersion(webAuthn4JVersion)
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


asciidoctorj{
    modules{
        diagram.use()
        diagram.version(libs.versions.asciidoctorj.diagram.get())
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
        "revnumber" to effectiveVersion
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
        "revnumber" to effectiveVersion
    ))
}

sonarqube {
    properties {
        property("sonar.projectKey", "webauthn4j")
        property("sonar.issue.ignore.multicriteria", "e1,e2,e3,e4,e5,e6,e7,e8")
        // Deep inheritance is acceptable for the attestation verifier hierarchy
        property("sonar.issue.ignore.multicriteria.e1.ruleKey", "java:S110")
        property("sonar.issue.ignore.multicriteria.e1.resourceKey", "**/*.java")
        // Generic wildcard types are used intentionally in public API signatures
        property("sonar.issue.ignore.multicriteria.e2.ruleKey", "java:S1452")
        property("sonar.issue.ignore.multicriteria.e2.resourceKey", "**/*.java")
        // Duplicated blocks across sync/async verifier pairs are intentional
        property("sonar.issue.ignore.multicriteria.e3.ruleKey", "common-java:DuplicatedBlocks")
        property("sonar.issue.ignore.multicriteria.e3.resourceKey", "**/*.java")
        // Multiple method invocations in exception tests are acceptable
        property("sonar.issue.ignore.multicriteria.e4.ruleKey", "java:S5778")
        property("sonar.issue.ignore.multicriteria.e4.resourceKey", "**/*.java")
        // @Deprecated since/forRemoval are added only when meaningful, not on every annotation
        property("sonar.issue.ignore.multicriteria.e5.ruleKey", "java:S6355")
        property("sonar.issue.ignore.multicriteria.e5.resourceKey", "**/*.java")
        // Exception classes are not designed for serialization; Serializable inherited from Throwable is not intentionally used
        property("sonar.issue.ignore.multicriteria.e6.ruleKey", "java:S1948")
        property("sonar.issue.ignore.multicriteria.e6.resourceKey", "**/*.java")
        // Nested if statements are kept separate intentionally for readability
        property("sonar.issue.ignore.multicriteria.e7.ruleKey", "java:S1066")
        property("sonar.issue.ignore.multicriteria.e7.resourceKey", "**/*.java")
        // Explicit if-then-else is preferred over single return for clarity
        property("sonar.issue.ignore.multicriteria.e8.ruleKey", "java:S1126")
        property("sonar.issue.ignore.multicriteria.e8.resourceKey", "**/*.java")
    }
}

val publishedSubprojects = subprojects.filter { it.name.startsWith("webauthn4j-") }

mavenCentralPublish {
    targetProjects = publishedSubprojects
    username = providers.environmentVariable("MAVEN_CENTRAL_USER")
    password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD")
}
