package com.webauthn4j.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.Configuration
import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.plugins.JavaPluginExtension
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.maven.plugins.MavenPublishPlugin

/**
 * A Gradle plugin that adds support for Maven-style optional dependencies.
 *
 * Creates a new `optional` configuration that is part of the project's compile
 * and runtime classpaths but does not affect the classpath of dependent projects.
 * When the `maven-publish` plugin is applied, optional dependencies are automatically
 * added to the generated POM with `<optional>true</optional>`.
 */
class OptionalDependenciesPlugin : Plugin<Project> {

    companion object {
        const val OPTIONAL_CONFIGURATION_NAME = "optional"
    }

    override fun apply(project: Project) {
        val optional = project.configurations.create(OPTIONAL_CONFIGURATION_NAME).apply {
            isCanBeConsumed = false
            isCanBeResolved = false
        }

        project.plugins.withType(JavaPlugin::class.java) {
            val sourceSets = project.extensions.getByType(JavaPluginExtension::class.java).sourceSets
            sourceSets.all {
                project.configurations.getByName(compileClasspathConfigurationName).extendsFrom(optional)
                project.configurations.getByName(runtimeClasspathConfigurationName).extendsFrom(optional)
            }
        }

        project.plugins.withType(MavenPublishPlugin::class.java) {
            project.extensions.getByType(PublishingExtension::class.java)
                .publications.withType(MavenPublication::class.java).configureEach {
                    pom {
                        withXml {
                            addOptionalDependencies(this, optional)
                        }
                    }
                }
        }
    }

    private fun addOptionalDependencies(xml: org.gradle.api.XmlProvider, optional: Configuration) {
        val root = xml.asNode()
        @Suppress("UNCHECKED_CAST")
        val depsNode = (root.get("dependencies") as? groovy.util.NodeList)
            ?.firstOrNull() as? groovy.util.Node
            ?: root.appendNode("dependencies")
        for (dep in optional.dependencies) {
            val depNode = depsNode.appendNode("dependency")
            depNode.appendNode("groupId", dep.group)
            depNode.appendNode("artifactId", dep.name)
            depNode.appendNode("version", dep.version)
            depNode.appendNode("scope", "compile")
            depNode.appendNode("optional", "true")
        }
    }
}
