package net.sharplab.gradle.mavencentral

import org.gradle.api.Project
import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty

/**
 * Extension for configuring Maven Central deployment via the Central Portal Publisher API.
 */
abstract class MavenCentralPublishExtension {

    /** Projects to publish to Maven Central. Each must have the `maven-publish` plugin applied. */
    abstract val targetProjects: SetProperty<Project>

    /** Sonatype Central Portal username */
    abstract val username: Property<String>

    /** Sonatype Central Portal password */
    abstract val password: Property<String>

    /** Deployment name shown in Central Portal UI */
    abstract val deploymentName: Property<String>

    /** Publishing type: AUTOMATIC or USER_MANAGED */
    abstract val publishingType: Property<String>

    /** Delay in seconds between status poll retries */
    abstract val retryDelay: Property<Int>

    /** Maximum number of status poll retries */
    abstract val maxRetries: Property<Int>

    /** Base URL for Central Portal API */
    abstract val apiBaseUrl: Property<String>
}
