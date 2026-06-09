package com.webauthn4j.gradle.toolchain

object ToolchainJdkVersionParser {

    fun isMajorVersionOnly(version: String): Boolean = version.all { it.isDigit() }

    fun extractMajorVersion(version: String): Int = version.substringBefore(".").toInt()
}
