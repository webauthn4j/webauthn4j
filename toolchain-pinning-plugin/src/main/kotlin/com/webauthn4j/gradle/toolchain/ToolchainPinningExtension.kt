package com.webauthn4j.gradle.toolchain

import org.gradle.api.provider.Property

abstract class ToolchainPinningExtension {
    abstract val toolchainJdkVersion: Property<String>
}
