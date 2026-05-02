package net.sharplab.gradle.mavencentral

import org.assertj.core.api.Assertions.assertThat
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class MavenCentralPublishPluginTest {

    @Nested
    inner class PluginApplicationTest {

        @Test
        fun `registers publishToCentralPortal task`(@TempDir projectDir: File) {
            writeSettingsFile(projectDir)
            File(projectDir, "build.gradle.kts").writeText("""
                plugins {
                    id("net.sharplab.maven-central-publish")
                }
            """.trimIndent())

            val result = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments("tasks", "--group=publishing")
                .build()

            assertThat(result.output).contains("publishToCentralPortal")
        }

        @Test
        fun `registers mavenCentralPublish extension`(@TempDir projectDir: File) {
            writeSettingsFile(projectDir)
            File(projectDir, "build.gradle.kts").writeText("""
                plugins {
                    id("net.sharplab.maven-central-publish")
                }
                mavenCentralPublish {
                    publishingType.set("USER_MANAGED")
                }
            """.trimIndent())

            val result = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments("tasks")
                .build()

            assertThat(result.output).contains("BUILD SUCCESSFUL")
        }
    }

    @Nested
    inner class TargetProjectsTest {

        @Test
        fun `adds mavenCentralStaging repository to subproject`(@TempDir projectDir: File) {
            setupMultiModuleProject(projectDir)

            val result = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments(":module-a:tasks", "--all")
                .build()

            assertThat(result.output).contains("publishAllPublicationsToMavenCentralStagingRepository")
        }

        @Test
        fun `publishToCentralPortal depends on subproject staging tasks`(@TempDir projectDir: File) {
            setupMultiModuleProject(projectDir)

            val result = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments("publishToCentralPortal", "--dry-run")
                .build()

            assertThat(result.output).contains(":module-a:publishAllPublicationsToMavenCentralStagingRepository")
            assertThat(result.output).contains(":module-b:publishAllPublicationsToMavenCentralStagingRepository")
        }

        @Test
        fun `stages artifacts to maven-central-publish-staging directory`(@TempDir projectDir: File) {
            setupMultiModuleProject(projectDir)

            val result = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments(":module-a:publishAllPublicationsToMavenCentralStagingRepository")
                .build()

            assertThat(result.task(":module-a:publishAllPublicationsToMavenCentralStagingRepository")?.outcome)
                .isEqualTo(TaskOutcome.SUCCESS)
            val stagingDir = File(projectDir, "module-a/build/maven-central-publish-staging")
            assertThat(stagingDir).isDirectory()
            assertThat(stagingDir.walkTopDown().filter { it.name.endsWith(".pom") }.toList()).isNotEmpty()
        }

        @Test
        fun `does not add repository to subproject without maven-publish`(@TempDir projectDir: File) {
            writeSettingsFile(projectDir, listOf("module-a", "module-test"))
            File(projectDir, "build.gradle.kts").writeText("""
                plugins {
                    id("net.sharplab.maven-central-publish")
                }
                mavenCentralPublish {
                    targetProjects.addAll(listOf(project(":module-a"), project(":module-test")))
                }
            """.trimIndent())

            // module-a has maven-publish
            File(projectDir, "module-a").mkdirs()
            File(projectDir, "module-a/build.gradle.kts").writeText("""
                plugins {
                    `java-library`
                    `maven-publish`
                }
                publishing {
                    publications {
                        create<MavenPublication>("maven") {
                            from(components["java"])
                        }
                    }
                }
            """.trimIndent())

            // module-test does NOT have maven-publish
            File(projectDir, "module-test").mkdirs()
            File(projectDir, "module-test/build.gradle.kts").writeText("""
                plugins {
                    `java-library`
                }
            """.trimIndent())

            val result = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments(":module-test:tasks", "--all")
                .build()

            assertThat(result.output).doesNotContain("mavenCentralStaging")
        }
    }

    @Nested
    inner class PublishToCentralPortalTaskTest {

        @Test
        fun `fails with clear message when credentials are missing`(@TempDir projectDir: File) {
            setupMultiModuleProject(projectDir)

            // Stage artifacts first
            GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments("publishAllPublicationsToMavenCentralStagingRepository")
                .build()

            // Try to deploy without credentials
            val result = GradleRunner.create()
                .withProjectDir(projectDir)
                .withPluginClasspath()
                .withArguments("publishToCentralPortal")
                .buildAndFail()

            assertThat(result.output).contains("username")
        }
    }

    private fun setupMultiModuleProject(projectDir: File) {
        writeSettingsFile(projectDir, listOf("module-a", "module-b"))
        File(projectDir, "build.gradle.kts").writeText("""
            plugins {
                id("net.sharplab.maven-central-publish")
            }
            group = "com.example"
            version = "1.0.0"
            subprojects {
                group = rootProject.group
                version = rootProject.version
            }
            mavenCentralPublish {
                targetProjects.addAll(subprojects)
            }
        """.trimIndent())

        for (module in listOf("module-a", "module-b")) {
            File(projectDir, module).mkdirs()
            File(projectDir, "$module/src/main/java").mkdirs()
            File(projectDir, "$module/src/main/java/Dummy.java").writeText("public class Dummy {}")
            File(projectDir, "$module/build.gradle.kts").writeText("""
                plugins {
                    `java-library`
                    `maven-publish`
                }
                publishing {
                    publications {
                        create<MavenPublication>("maven") {
                            from(components["java"])
                        }
                    }
                }
            """.trimIndent())
        }
    }

    private fun writeSettingsFile(projectDir: File, modules: List<String> = emptyList()) {
        val includes = modules.joinToString("\n") { "include(\"$it\")" }
        File(projectDir, "settings.gradle.kts").writeText("""
            rootProject.name = "test-project"
            $includes
        """.trimIndent())
    }
}
