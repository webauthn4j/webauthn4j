package com.webauthn4j.gradle

object VersionUtils {

    @JvmStatic
    fun getEffectiveVersion(isSnapshot: Boolean, webAuthn4JVersion: String): String {
        return if (isSnapshot) {
            webAuthn4JVersion + "-SNAPSHOT"
        } else {
            webAuthn4JVersion + ".RELEASE"
        }
    }

    @JvmStatic
    fun bumpPatchVersion(version: String): String {
        val parts = version.split(".")
        require(parts.size == 3) { "Version must be in the format 'X.Y.Z': $version" }

        val major = parts[0].toInt()
        val minor = parts[1].toInt()
        val patch = parts[2].toInt() + 1

        return "$major.$minor.$patch"
    }
}
