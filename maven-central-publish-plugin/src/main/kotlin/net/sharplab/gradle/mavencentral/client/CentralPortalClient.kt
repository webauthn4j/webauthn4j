package net.sharplab.gradle.mavencentral.client

import com.fasterxml.jackson.databind.ObjectMapper
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.UUID

/**
 * HTTP client for the Sonatype Central Portal Publisher API.
 */
class CentralPortalClient(
    private val apiBaseUrl: String,
    username: String,
    password: String
) {
    private val authToken: String = Base64.getEncoder()
        .encodeToString("$username:$password".toByteArray(StandardCharsets.UTF_8))

    private val httpClient: HttpClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

    private val objectMapper: ObjectMapper = ObjectMapper()

    /**
     * Uploads the ZIP bundle to Central Portal.
     * @return the deployment ID
     */
    fun upload(zipBytes: ByteArray, name: String, publishingType: String): String {
        val boundary = UUID.randomUUID().toString()
        val bodyBytes = buildMultipartBody(boundary, "bundle", "$name.zip", zipBytes)

        val request = HttpRequest.newBuilder()
            .uri(URI.create("$apiBaseUrl/upload?publishingType=$publishingType&name=$name"))
            .header("Authorization", "Bearer $authToken")
            .header("Content-Type", "multipart/form-data; boundary=$boundary")
            .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes))
            .build()

        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 201) {
            throw CentralPortalApiException(response.statusCode(), response.body())
        }

        return response.body().trim()
    }

    /**
     * Queries the deployment status.
     */
    fun getStatus(deploymentId: String): DeploymentStatus {
        val request = HttpRequest.newBuilder()
            .uri(URI.create("$apiBaseUrl/status?id=$deploymentId"))
            .header("Authorization", "Bearer $authToken")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build()

        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

        if (response.statusCode() != 200) {
            throw CentralPortalApiException(response.statusCode(), response.body())
        }

        val tree = objectMapper.readTree(response.body())
        val state = tree.get("deploymentState")?.asText()
            ?: throw CentralPortalApiException(response.statusCode(), response.body())
        val errorsNode = tree.get("errors")
        val errors: List<String>? = if (errorsNode != null && errorsNode.isArray) {
            val list = mutableListOf<String>()
            for (node in errorsNode) {
                list.add(node.asText())
            }
            list
        } else {
            null
        }

        return DeploymentStatus(
            deploymentState = state,
            errors = errors
        )
    }

    /**
     * Builds a multipart/form-data body manually.
     */
    private fun buildMultipartBody(
        boundary: String,
        fieldName: String,
        fileName: String,
        fileContent: ByteArray
    ): ByteArray {
        val baos = ByteArrayOutputStream()
        val lineEnd = "\r\n"

        baos.write("--$boundary$lineEnd".toByteArray())
        baos.write(
            "Content-Disposition: form-data; name=\"$fieldName\"; filename=\"$fileName\"$lineEnd"
                .toByteArray()
        )
        baos.write("Content-Type: application/octet-stream$lineEnd".toByteArray())
        baos.write(lineEnd.toByteArray())

        baos.write(fileContent)
        baos.write(lineEnd.toByteArray())

        baos.write("--$boundary--$lineEnd".toByteArray())

        return baos.toByteArray()
    }
}
