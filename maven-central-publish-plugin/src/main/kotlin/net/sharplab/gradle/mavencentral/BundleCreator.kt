package net.sharplab.gradle.mavencentral

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Creates a ZIP deployment bundle from staging directories in Maven repository layout.
 */
object BundleCreator {

    /**
     * Creates a ZIP bundle from staging directories.
     * Files from all directories are merged into a single ZIP,
     * preserving their relative paths in Maven repository layout.
     */
    fun createZipBundle(stagingDirs: List<File>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            for (stagingDir in stagingDirs) {
                stagingDir.walkTopDown()
                    .filter { it.isFile }
                    .forEach { file ->
                        val relativePath = stagingDir.toPath().relativize(file.toPath()).toString()
                        zos.putNextEntry(ZipEntry(relativePath))
                        Files.copy(file.toPath(), zos)
                        zos.closeEntry()
                    }
            }
        }
        return baos.toByteArray()
    }
}
