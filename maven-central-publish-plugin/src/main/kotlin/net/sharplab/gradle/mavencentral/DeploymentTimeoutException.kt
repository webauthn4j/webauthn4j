package net.sharplab.gradle.mavencentral

/**
 * Thrown when status polling exceeds the configured maximum number of retries.
 */
class DeploymentTimeoutException(
    val deploymentId: String,
    val lastState: String,
    val maxRetries: Int,
    val retryDelay: Int
) : RuntimeException(
    "Deployment $deploymentId did not complete within ${maxRetries * retryDelay} seconds. " +
        "Last state: $lastState"
)
