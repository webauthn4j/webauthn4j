package net.sharplab.gradle.mavencentral

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.publish.PublishingExtension

/**
 * Gradle plugin that aggregates artifacts from multiple subprojects and publishes them
 * to Maven Central as a single bundle via the Central Portal Publisher API.
 *
 * Credentials are resolved automatically from environment variables
 * (`MAVEN_CENTRAL_USER`, `MAVEN_CENTRAL_PASSWORD`) or Gradle project properties
 * (`mavenCentralUser`, `mavenCentralPassword`).
 */
class MavenCentralPublishPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val extension = project.extensions.create(
            "mavenCentralPublish",
            MavenCentralPublishExtension::class.java
        )

        extension.publishingType.convention("AUTOMATIC")
        extension.retryDelay.convention(10)
        extension.maxRetries.convention(1000)
        extension.apiBaseUrl.convention("https://central.sonatype.com/api/v1/publisher")
        extension.deploymentName.convention(
            project.provider { "${project.group}:${project.name}:${project.version}" }
        )

        val taskProvider = project.tasks.register(
            "publishToCentralPortal",
            PublishToCentralPortalTask::class.java
        )
        taskProvider.configure {
            description = "Publishes aggregated artifacts to Maven Central via the Central Portal Publisher API"
            group = "publishing"

            username.set(extension.username)
            password.set(extension.password)
            deploymentName.set(extension.deploymentName)
            publishingType.set(extension.publishingType)
            retryDelay.set(extension.retryDelay)
            maxRetries.set(extension.maxRetries)
            apiBaseUrl.set(extension.apiBaseUrl)
        }

        // After the build script has been evaluated, configure staging repositories
        // and task dependencies based on the declared targetProjects.
        project.afterEvaluate {
            for (subproject in extension.targetProjects.get()) {
                subproject.pluginManager.withPlugin("maven-publish") {
                    val stagingDir = subproject.layout.buildDirectory.dir("maven-central-publish-staging")

                    subproject.extensions.configure(PublishingExtension::class.java) {
                        repositories.maven {
                            name = "mavenCentralStaging"
                            url = stagingDir.get().asFile.toURI()
                        }
                    }

                    taskProvider.configure {
                        stagingDirectories.from(stagingDir)
                    }
                }

                taskProvider.configure {
                    dependsOn("${subproject.path}:publishAllPublicationsToMavenCentralStagingRepository")
                }
            }
        }
    }

}
