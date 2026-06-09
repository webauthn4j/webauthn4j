package com.webauthn4j.gradle.toolchain

import org.gradle.jvm.toolchain.JavaToolchainDownload
import org.gradle.jvm.toolchain.JavaToolchainRequest
import org.gradle.jvm.toolchain.JavaToolchainResolver
import org.gradle.platform.Architecture
import org.gradle.platform.OperatingSystem
import java.net.URI
import java.net.URLEncoder
import java.util.*

abstract class AdoptiumToolchainResolver : JavaToolchainResolver {

    var toolchainJdkVersion: String? = null

    override fun resolve(request: JavaToolchainRequest): Optional<JavaToolchainDownload> {
        val platform = request.buildPlatform
        val os = mapOperatingSystem(platform.operatingSystem)
        val arch = mapArchitecture(platform.architecture)

        val version = toolchainJdkVersion
        if (version == null) {
            return resolveLatest(request.javaToolchainSpec.languageVersion.get().asInt(), os, arch)
        }
        else if (ToolchainJdkVersionParser.isMajorVersionOnly(version)) {
            return resolveLatest(version.toInt(), os, arch)
        } else {
            return resolveExact(version, os, arch)
        }
    }

    private fun resolveExact(version: String, os: String, arch: String): Optional<JavaToolchainDownload> {
        val encodedVersion = URLEncoder.encode(version, Charsets.UTF_8)
        val url = URI("https://api.adoptium.net/v3/binary/version/jdk-$encodedVersion/$os/$arch/jdk/hotspot/normal/eclipse?project=jdk")
        return Optional.of(JavaToolchainDownload.fromUri(url))
    }

    private fun resolveLatest(majorVersion: Int, os: String, arch: String): Optional<JavaToolchainDownload> {
        val url = URI("https://api.adoptium.net/v3/binary/latest/$majorVersion/ga/$os/$arch/jdk/hotspot/normal/eclipse?project=jdk")
        return Optional.of(JavaToolchainDownload.fromUri(url))
    }

    private fun mapOperatingSystem(os: OperatingSystem): String = when (os) {
        OperatingSystem.LINUX -> "linux"
        OperatingSystem.WINDOWS -> "windows"
        OperatingSystem.MAC_OS -> "mac"
        else -> throw IllegalArgumentException("Unsupported operating system: $os")
    }

    private fun mapArchitecture(arch: Architecture): String = when (arch) {
        Architecture.X86_64 -> "x64"
        Architecture.AARCH64 -> "aarch64"
        else -> throw IllegalArgumentException("Unsupported architecture: $arch")
    }
}
