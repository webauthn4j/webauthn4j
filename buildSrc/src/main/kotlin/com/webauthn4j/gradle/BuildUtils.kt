package com.webauthn4j.gradle

import org.gradle.api.Project

/**
 * Utility class providing helper functions for build scripts
 */
object BuildUtils {
    /**
     * Retrieves a value from either an environment variable or a project property
     * @param project The current project
     * @param envName The name of the environment variable
     * @param propertyName The name of the project property
     * @return The value, or null if neither exists
     */
    fun getVariable(project: Project, envName: String, propertyName: String): String? {
        return if (System.getenv(envName) != null && System.getenv(envName).isNotEmpty()) {
            System.getenv(envName)
        } else if (project.hasProperty(propertyName)) {
            project.property(propertyName) as String?
        } else {
            null
        }
    }
}