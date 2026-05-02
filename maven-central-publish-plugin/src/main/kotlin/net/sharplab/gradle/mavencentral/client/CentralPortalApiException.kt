package net.sharplab.gradle.mavencentral.client

/**
 * Thrown when the Central Portal Publisher API returns an unexpected response.
 */
class CentralPortalApiException(
    val statusCode: Int,
    val responseBody: String,
    message: String = "Central Portal API error (status $statusCode): $responseBody"
) : RuntimeException(message)
