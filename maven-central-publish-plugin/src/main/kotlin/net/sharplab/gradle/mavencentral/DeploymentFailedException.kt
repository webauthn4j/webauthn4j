package net.sharplab.gradle.mavencentral

/**
 * Thrown when a deployment reaches the FAILED state on Central Portal.
 */
class DeploymentFailedException(
    val deploymentId: String,
    val errors: List<String>
) : RuntimeException(
    "Deployment $deploymentId failed:\n${errors.joinToString("\n")}"
)
