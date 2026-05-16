package net.sharplab.gradle.mavencentral

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.assertj.core.api.Assertions.assertThat
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.zip.ZipInputStream

class MavenCentralPublishPluginIntegrationTest {

    private lateinit var server: MockWebServer
    private val recordedRequests = CopyOnWriteArrayList<RecordedRequest>()

    @BeforeEach
    fun setUp() {
        server = MockWebServer()

        // Simulate Central Portal: upload returns 201, status returns PUBLISHED immediately
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                recordedRequests.add(request)
                return when {
                    request.path?.startsWith("/api/v1/publisher/upload") == true -> {
                        MockResponse().setResponseCode(201).setBody("test-deployment-id")
                    }
                    request.path?.startsWith("/api/v1/publisher/status") == true -> {
                        MockResponse().setBody("""
                            {
                                "deploymentId": "test-deployment-id",
                                "deploymentState": "PUBLISHED",
                                "errors": []
                            }
                        """.trimIndent())
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }

        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `publishes staged artifacts to mock Central Portal`(@TempDir projectDir: File) {
        setupProject(projectDir)

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("publishToCentralPortal")
            .build()

        assertThat(result.task(":publishToCentralPortal")?.outcome).isEqualTo(TaskOutcome.SUCCESS)
        assertThat(result.output).contains("Deployment published successfully!")
    }

    @Test
    fun `uploads a valid ZIP bundle containing all modules`(@TempDir projectDir: File) {
        setupProject(projectDir)

        GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("publishToCentralPortal")
            .build()

        val uploadRequest = recordedRequests.first { it.path?.contains("/upload") == true }

        // Extract ZIP from multipart body
        val body = uploadRequest.body.readByteArray()
        val zipBytes = extractZipFromMultipart(body, uploadRequest.getHeader("Content-Type")!!)
        val entries = readZipEntries(zipBytes)

        // Should contain POM files for both modules
        val pomEntries = entries.keys.filter { it.endsWith(".pom") }
        assertThat(pomEntries).hasSize(2)
        assertThat(pomEntries).anyMatch { it.contains("module-a") }
        assertThat(pomEntries).anyMatch { it.contains("module-b") }

        // Should contain JAR files for both modules
        val jarEntries = entries.keys.filter { it.endsWith(".jar") && !it.contains("sources") && !it.contains("javadoc") }
        assertThat(jarEntries).hasSize(2)
    }

    @Test
    fun `sends correct authentication header`(@TempDir projectDir: File) {
        setupProject(projectDir)

        GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("publishToCentralPortal")
            .build()

        val uploadRequest = recordedRequests.first { it.path?.contains("/upload") == true }
        val expectedToken = Base64.getEncoder()
            .encodeToString("testUser:testPassword".toByteArray(StandardCharsets.UTF_8))
        assertThat(uploadRequest.getHeader("Authorization")).isEqualTo("Bearer $expectedToken")
    }

    @Test
    fun `sends correct query parameters`(@TempDir projectDir: File) {
        setupProject(projectDir)

        GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("publishToCentralPortal")
            .build()

        val uploadRequest = recordedRequests.first { it.path?.contains("/upload") == true }
        assertThat(uploadRequest.path).contains("publishingType=AUTOMATIC")
    }

    @Test
    fun `fails when deployment reaches FAILED state`(@TempDir projectDir: File) {
        // Override dispatcher to return FAILED
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                return when {
                    request.path?.startsWith("/api/v1/publisher/upload") == true -> {
                        MockResponse().setResponseCode(201).setBody("test-deployment-id")
                    }
                    request.path?.startsWith("/api/v1/publisher/status") == true -> {
                        MockResponse().setBody("""
                            {
                                "deploymentId": "test-deployment-id",
                                "deploymentState": "FAILED",
                                "errors": ["Invalid POM metadata"]
                            }
                        """.trimIndent())
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }

        setupProject(projectDir)

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("publishToCentralPortal")
            .buildAndFail()

        assertThat(result.output).contains("Invalid POM metadata")
    }

    @Test
    fun `polls through state transitions until PUBLISHED`(@TempDir projectDir: File) {
        val states = listOf("PENDING", "VALIDATING", "VALIDATED", "PUBLISHING", "PUBLISHED")
        val statusCallCount = java.util.concurrent.atomic.AtomicInteger(0)

        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                recordedRequests.add(request)
                return when {
                    request.path?.startsWith("/api/v1/publisher/upload") == true -> {
                        MockResponse().setResponseCode(201).setBody("test-deployment-id")
                    }
                    request.path?.startsWith("/api/v1/publisher/status") == true -> {
                        val idx = statusCallCount.getAndIncrement().coerceAtMost(states.size - 1)
                        MockResponse().setBody("""
                            {
                                "deploymentId": "test-deployment-id",
                                "deploymentState": "${states[idx]}",
                                "errors": []
                            }
                        """.trimIndent())
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }

        setupProject(projectDir, retryDelay = 1)

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("publishToCentralPortal")
            .build()

        assertThat(result.task(":publishToCentralPortal")?.outcome).isEqualTo(TaskOutcome.SUCCESS)
        assertThat(result.output).contains("Deployment state: PENDING")
        assertThat(result.output).contains("Deployment state: PUBLISHED")
        assertThat(result.output).contains("Deployment published successfully!")

        val statusRequests = recordedRequests.filter { it.path?.contains("/status") == true }
        assertThat(statusRequests.size).isGreaterThanOrEqualTo(states.size)
    }

    @Test
    fun `times out when deployment stays in PENDING`(@TempDir projectDir: File) {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                return when {
                    request.path?.startsWith("/api/v1/publisher/upload") == true -> {
                        MockResponse().setResponseCode(201).setBody("test-deployment-id")
                    }
                    request.path?.startsWith("/api/v1/publisher/status") == true -> {
                        MockResponse().setBody("""
                            {
                                "deploymentId": "test-deployment-id",
                                "deploymentState": "PENDING",
                                "errors": []
                            }
                        """.trimIndent())
                    }
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }

        setupProject(projectDir, retryDelay = 1, maxRetries = 3)

        val result = GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments("publishToCentralPortal")
            .buildAndFail()

        assertThat(result.output).contains("did not complete within")
        assertThat(result.output).contains("Last state: PENDING")
    }

    private fun setupProject(projectDir: File, retryDelay: Int = 10, maxRetries: Int = 1000) {
        val serverUrl = server.url("/api/v1/publisher").toString().trimEnd('/')

        writeSettingsFile(projectDir, listOf("module-a", "module-b"))
        File(projectDir, "build.gradle.kts").writeText("""
            plugins {
                id("net.sharplab.maven-central-publish")
            }
            group = "com.example"
            version = "1.0.0"
            subprojects {
                group = rootProject.group
                version = rootProject.version
            }
            mavenCentralPublish {
                targetProjects.addAll(subprojects)
                username = "testUser"
                password = "testPassword"
                apiBaseUrl = "$serverUrl"
                retryDelay = $retryDelay
                maxRetries = $maxRetries
            }
        """.trimIndent())

        for (module in listOf("module-a", "module-b")) {
            File(projectDir, module).mkdirs()
            File(projectDir, "$module/src/main/java").mkdirs()
            File(projectDir, "$module/src/main/java/Dummy.java").writeText("public class Dummy {}")
            File(projectDir, "$module/build.gradle.kts").writeText("""
                plugins {
                    `java-library`
                    `maven-publish`
                }
                publishing {
                    publications {
                        create<MavenPublication>("maven") {
                            from(components["java"])
                        }
                    }
                }
            """.trimIndent())
        }
    }

    private fun writeSettingsFile(projectDir: File, modules: List<String>) {
        val includes = modules.joinToString("\n") { "include(\"$it\")" }
        File(projectDir, "settings.gradle.kts").writeText("""
            rootProject.name = "test-project"
            $includes
        """.trimIndent())
    }

    private fun extractZipFromMultipart(body: ByteArray, contentType: String): ByteArray {
        val boundary = contentType.substringAfter("boundary=").trim()
        val bodyStr = String(body, StandardCharsets.ISO_8859_1)

        // Find the binary content between the headers and the closing boundary
        val headerEnd = "\r\n\r\n"
        val headerEndIdx = bodyStr.indexOf(headerEnd)
        val contentStart = headerEndIdx + headerEnd.length
        val closingBoundary = "\r\n--$boundary--"
        val contentEnd = bodyStr.indexOf(closingBoundary, contentStart)

        return body.copyOfRange(contentStart, contentEnd)
    }

    private fun readZipEntries(zipBytes: ByteArray): Map<String, ByteArray> {
        val entries = mutableMapOf<String, ByteArray>()
        ZipInputStream(zipBytes.inputStream()).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                entries[entry.name] = zis.readBytes()
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }
        return entries
    }
}
