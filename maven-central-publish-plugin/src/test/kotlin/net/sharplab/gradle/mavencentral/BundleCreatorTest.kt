package net.sharplab.gradle.mavencentral

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.zip.ZipInputStream

class BundleCreatorTest {

    @Test
    fun `creates ZIP from single staging directory`(@TempDir tempDir: File) {
        val stagingDir = File(tempDir, "staging").apply { mkdirs() }
        val artifactDir = File(stagingDir, "com/example/mylib/1.0").apply { mkdirs() }
        File(artifactDir, "mylib-1.0.jar").writeText("jar-content")
        File(artifactDir, "mylib-1.0.pom").writeText("pom-content")

        val zipBytes = BundleCreator.createZipBundle(listOf(stagingDir))

        val entries = readZipEntries(zipBytes)
        assertThat(entries).containsKeys(
            "com/example/mylib/1.0/mylib-1.0.jar",
            "com/example/mylib/1.0/mylib-1.0.pom"
        )
        assertThat(entries["com/example/mylib/1.0/mylib-1.0.jar"]).isEqualTo("jar-content")
        assertThat(entries["com/example/mylib/1.0/mylib-1.0.pom"]).isEqualTo("pom-content")
    }

    @Test
    fun `creates ZIP from multiple staging directories`(@TempDir tempDir: File) {
        val stagingA = File(tempDir, "staging-a").apply { mkdirs() }
        File(stagingA, "com/example/module-a/1.0").mkdirs()
        File(stagingA, "com/example/module-a/1.0/module-a-1.0.jar").writeText("a-content")

        val stagingB = File(tempDir, "staging-b").apply { mkdirs() }
        File(stagingB, "com/example/module-b/1.0").mkdirs()
        File(stagingB, "com/example/module-b/1.0/module-b-1.0.jar").writeText("b-content")

        val zipBytes = BundleCreator.createZipBundle(listOf(stagingA, stagingB))

        val entries = readZipEntries(zipBytes)
        assertThat(entries).containsKeys(
            "com/example/module-a/1.0/module-a-1.0.jar",
            "com/example/module-b/1.0/module-b-1.0.jar"
        )
        assertThat(entries["com/example/module-a/1.0/module-a-1.0.jar"]).isEqualTo("a-content")
        assertThat(entries["com/example/module-b/1.0/module-b-1.0.jar"]).isEqualTo("b-content")
    }

    @Test
    fun `creates empty ZIP from empty directory`(@TempDir tempDir: File) {
        val stagingDir = File(tempDir, "staging").apply { mkdirs() }

        val zipBytes = BundleCreator.createZipBundle(listOf(stagingDir))

        val entries = readZipEntries(zipBytes)
        assertThat(entries).isEmpty()
    }

    private fun readZipEntries(zipBytes: ByteArray): Map<String, String> {
        val entries = mutableMapOf<String, String>()
        ZipInputStream(zipBytes.inputStream()).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                entries[entry.name] = zis.readBytes().toString(StandardCharsets.UTF_8)
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }
        return entries
    }
}
