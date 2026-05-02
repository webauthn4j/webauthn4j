package net.sharplab.gradle.mavencentral.client

/**
 * Deployment status returned by the Central Portal Publisher API.
 */
data class DeploymentStatus(
    val deploymentState: String,
    val errors: List<String>?
)
