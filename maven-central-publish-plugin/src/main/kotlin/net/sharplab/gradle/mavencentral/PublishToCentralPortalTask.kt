package net.sharplab.gradle.mavencentral

import net.sharplab.gradle.mavencentral.client.CentralPortalClient
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction

/**
 * Task that publishes aggregated artifacts to Maven Central
 * as a single bundle via the Central Portal Publisher API.
 *
 * This ensures atomic publishing of all modules in a multi-project build.
 */
abstract class PublishToCentralPortalTask : DefaultTask() {

    @get:InputFiles
    abstract val stagingDirectories: ConfigurableFileCollection

    @get:Internal
    abstract val username: Property<String>

    @get:Internal
    abstract val password: Property<String>

    @get:Input
    abstract val deploymentName: Property<String>

    @get:Input
    abstract val publishingType: Property<String>

    @get:Internal
    abstract val retryDelay: Property<Int>

    @get:Internal
    abstract val maxRetries: Property<Int>

    @get:Internal
    abstract val apiBaseUrl: Property<String>

    init {
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun publish() {
        val stagingDirs = collectStagingDirectories()

        logger.lifecycle("Creating deployment bundle from ${stagingDirs.size} staging directories")

        val zipBytes = BundleCreator.createZipBundle(stagingDirs)
        logger.lifecycle("Created bundle: ${zipBytes.size} bytes")

        val client = CentralPortalClient(
            apiBaseUrl = apiBaseUrl.get(),
            username = username.get(),
            password = password.get()
        )

        val deploymentId = client.upload(
            zipBytes = zipBytes,
            name = deploymentName.get(),
            publishingType = publishingType.get()
        )
        logger.lifecycle("Upload complete. Deployment ID: $deploymentId")

        awaitPublished(client, deploymentId)
    }

    private fun collectStagingDirectories(): List<java.io.File> {
        val dirs = stagingDirectories.files
            .filter { it.exists() && it.isDirectory }
            .toList()

        if (dirs.isEmpty()) {
            throw GradleException("No staging directories found")
        }

        val totalFiles = dirs.sumOf { dir ->
            dir.walkTopDown().filter { it.isFile }.count()
        }
        if (totalFiles == 0) {
            throw GradleException("All staging directories are empty")
        }

        return dirs
    }

    private fun awaitPublished(client: CentralPortalClient, deploymentId: String) {
        val maxRetries = maxRetries.get()
        val retryDelay = retryDelay.get()
        var lastState = ""

        for (attempt in 1..maxRetries) {
            val status = client.getStatus(deploymentId)
            val state = status.deploymentState

            if (state != lastState) {
                logger.lifecycle("Deployment state: $state")
                lastState = state
            }

            when (state) {
                "PUBLISHED" -> {
                    logger.lifecycle("Deployment published successfully!")
                    return
                }
                "FAILED" -> {
                    throw DeploymentFailedException(
                        deploymentId = deploymentId,
                        errors = status.errors ?: listOf("No error details available")
                    )
                }
                "PENDING", "VALIDATING", "VALIDATED", "PUBLISHING" -> {
                    if (attempt < maxRetries) {
                        Thread.sleep(retryDelay * 1000L)
                    }
                }
                else -> {
                    logger.warn("Unknown deployment state: $state")
                    if (attempt < maxRetries) {
                        Thread.sleep(retryDelay * 1000L)
                    }
                }
            }
        }

        throw DeploymentTimeoutException(
            deploymentId = deploymentId,
            lastState = lastState,
            maxRetries = maxRetries,
            retryDelay = retryDelay
        )
    }
}
