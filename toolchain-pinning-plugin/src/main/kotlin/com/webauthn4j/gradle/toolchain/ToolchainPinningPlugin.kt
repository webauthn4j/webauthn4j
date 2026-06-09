package com.webauthn4j.gradle.toolchain

import org.gradle.api.Plugin
import org.gradle.api.initialization.Settings
import org.gradle.api.internal.SettingsInternal
import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.plugins.JvmToolchainManagementPlugin
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.jvm.toolchain.JavaToolchainResolverRegistry
import org.gradle.kotlin.dsl.jvm
import org.gradle.kotlin.dsl.the

abstract class ToolchainPinningPlugin : Plugin<Settings> {

    override fun apply(target: Settings) {
        val extension = target.extensions.create(
            "toolchainPinning",
            ToolchainPinningExtension::class.java
        )

        target.gradle.settingsEvaluated {
            val toolchainJdkVersion = extension.toolchainJdkVersion.orNull

            // Pass the version to the resolver instance via shared build services.
            target.gradle.sharedServices.registrations.forEach { registration ->
                val service = registration.service.orNull
                if (service is AdoptiumToolchainResolver) {
                    service.toolchainJdkVersion = toolchainJdkVersion
                }
            }

            // When an exact version is specified (e.g. 25.0.3+9), disable local JDK
            // auto-detection to force downloading and using the pinned version.
            if (toolchainJdkVersion != null && !ToolchainJdkVersionParser.isMajorVersionOnly(toolchainJdkVersion)) {
                System.setProperty("org.gradle.java.installations.auto-detect", "false")
            }
        }

        target.gradle.allprojects {
            plugins.withType(JavaPlugin::class.java) {
                val toolchainJdkVersion = extension.toolchainJdkVersion.orNull
                if (toolchainJdkVersion != null) {
                    the<org.gradle.api.plugins.JavaPluginExtension>().toolchain {
                        languageVersion.set(JavaLanguageVersion.of(ToolchainJdkVersionParser.extractMajorVersion(toolchainJdkVersion)))
                    }
                }
            }
        }

        target.plugins.apply(JvmToolchainManagementPlugin::class.java)

        val registry = (target as SettingsInternal).services.get(JavaToolchainResolverRegistry::class.java)
        registry.register(AdoptiumToolchainResolver::class.java)

        @Suppress("UnstableApiUsage")
        target.toolchainManagement {
            jvm {
                javaRepositories {
                    repository("adoptium") {
                        resolverClass.set(AdoptiumToolchainResolver::class.java)
                    }
                }
            }
        }
    }
}
