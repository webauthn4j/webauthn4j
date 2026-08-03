package com.webauthn4j.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.testing.Test
import java.io.File

class TestWithSecurityProviderPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val extension = project.extensions.create(
            "testWithSecurityProvider",
            TestWithSecurityProviderExtension::class.java
        )

        val agentJar = resolveAgentJar()
        val generatedDir = project.layout.buildDirectory.dir("generated-security")

        project.afterEvaluate {
            extension.configurations.forEach { config ->
                val securityFile = generatedDir.get().file("${config.name}.security").asFile
                generateSecurityProperties(securityFile, config)

                val providerClasses = config.providers.get()
                    .map { it.split(" ").first() }
                    .joinToString(",")

                project.tasks.named(config.name, Test::class.java).configure {
                    jvmArgs("-javaagent:${agentJar.absolutePath}")
                    systemProperty("java.security.properties",
                        securityFile.absolutePath)
                    systemProperty("webauthn4j.test.securityProviders", providerClasses)
                    config.securityProperties.get().forEach { (key, value) ->
                        systemProperty("webauthn4j.test.security.$key", value)
                    }
                }
            }
        }
    }

    private fun generateSecurityProperties(file: File, config: SecurityProviderConfiguration) {
        file.parentFile.mkdirs()
        val lines = config.providers.get().mapIndexed { i, provider ->
            "security.provider.${i + 1}=$provider"
        }
        file.writeText(lines.joinToString("\n") + "\n")
    }

    private fun resolveAgentJar(): File {
        val pluginJar = TestWithSecurityProviderPlugin::class.java
            .protectionDomain
            .codeSource
            .location
            .toURI()
        return File(pluginJar)
    }
}
