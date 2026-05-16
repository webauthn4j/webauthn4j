package net.sharplab.gradle.mavencentral.client

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.Base64

class CentralPortalClientTest {

    private lateinit var server: MockWebServer
    private lateinit var client: CentralPortalClient

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = CentralPortalClient(
            apiBaseUrl = server.url("/api/v1/publisher").toString().trimEnd('/'),
            username = "testUser",
            password = "testPassword"
        )
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    @Nested
    inner class UploadTest {

        @Test
        fun `uploads bundle and returns deployment ID`() {
            server.enqueue(MockResponse().setResponseCode(201).setBody("test-deployment-id"))

            val deploymentId = client.upload(
                zipBytes = "fake-zip".toByteArray(),
                name = "com.example:mylib:1.0",
                publishingType = "AUTOMATIC"
            )

            assertThat(deploymentId).isEqualTo("test-deployment-id")
        }

        @Test
        fun `sends correct query parameters`() {
            server.enqueue(MockResponse().setResponseCode(201).setBody("id"))

            client.upload(
                zipBytes = "zip".toByteArray(),
                name = "com.example:mylib:1.0",
                publishingType = "AUTOMATIC"
            )

            val request = server.takeRequest()
            assertThat(request.path).contains("publishingType=AUTOMATIC")
            assertThat(request.path).contains("name=com.example:mylib:1.0")
        }

        @Test
        fun `sends correct authorization header`() {
            server.enqueue(MockResponse().setResponseCode(201).setBody("id"))

            client.upload(zipBytes = "zip".toByteArray(), name = "test", publishingType = "AUTOMATIC")

            val request = server.takeRequest()
            val expectedToken = Base64.getEncoder()
                .encodeToString("testUser:testPassword".toByteArray(StandardCharsets.UTF_8))
            assertThat(request.getHeader("Authorization")).isEqualTo("Bearer $expectedToken")
        }

        @Test
        fun `sends multipart form data with bundle field`() {
            server.enqueue(MockResponse().setResponseCode(201).setBody("id"))

            client.upload(zipBytes = "zip-data".toByteArray(), name = "test", publishingType = "AUTOMATIC")

            val request = server.takeRequest()
            assertThat(request.getHeader("Content-Type")).startsWith("multipart/form-data; boundary=")
            val body = request.body.readUtf8()
            assertThat(body).contains("Content-Disposition: form-data; name=\"bundle\"")
            assertThat(body).contains("zip-data")
        }

        @Test
        fun `throws CentralPortalApiException on non-201 response`() {
            server.enqueue(MockResponse().setResponseCode(400).setBody("Bad Request"))

            assertThatThrownBy {
                client.upload(zipBytes = "zip".toByteArray(), name = "test", publishingType = "AUTOMATIC")
            }
                .isInstanceOf(CentralPortalApiException::class.java)
                .satisfies({ ex ->
                    ex as CentralPortalApiException
                    assertThat(ex.statusCode).isEqualTo(400)
                    assertThat(ex.responseBody).isEqualTo("Bad Request")
                })
        }
    }

    @Nested
    inner class GetStatusTest {

        @Test
        fun `parses PUBLISHED state`() {
            server.enqueue(MockResponse().setBody(statusJson("PUBLISHED")))

            val status = client.getStatus("test-id")

            assertThat(status.deploymentState).isEqualTo("PUBLISHED")
            assertThat(status.errors).isEmpty()
        }

        @Test
        fun `parses PENDING state`() {
            server.enqueue(MockResponse().setBody(statusJson("PENDING")))

            val status = client.getStatus("test-id")

            assertThat(status.deploymentState).isEqualTo("PENDING")
        }

        @Test
        fun `parses FAILED state with errors`() {
            val json = """
                {
                    "deploymentId": "test-id",
                    "deploymentState": "FAILED",
                    "errors": ["Invalid POM", "Missing signature"]
                }
            """.trimIndent()
            server.enqueue(MockResponse().setBody(json))

            val status = client.getStatus("test-id")

            assertThat(status.deploymentState).isEqualTo("FAILED")
            assertThat(status.errors).containsExactly("Invalid POM", "Missing signature")
        }

        @Test
        fun `sends correct request`() {
            server.enqueue(MockResponse().setBody(statusJson("PENDING")))

            client.getStatus("my-deployment-id")

            val request = server.takeRequest()
            assertThat(request.method).isEqualTo("POST")
            assertThat(request.path).isEqualTo("/api/v1/publisher/status?id=my-deployment-id")
        }

        @Test
        fun `throws CentralPortalApiException on non-200 response`() {
            server.enqueue(MockResponse().setResponseCode(500).setBody("Internal Server Error"))

            assertThatThrownBy { client.getStatus("test-id") }
                .isInstanceOf(CentralPortalApiException::class.java)
                .satisfies({ ex ->
                    ex as CentralPortalApiException
                    assertThat(ex.statusCode).isEqualTo(500)
                })
        }
    }

    private fun statusJson(state: String): String = """
        {
            "deploymentId": "test-id",
            "deploymentState": "$state",
            "errors": []
        }
    """.trimIndent()

}
