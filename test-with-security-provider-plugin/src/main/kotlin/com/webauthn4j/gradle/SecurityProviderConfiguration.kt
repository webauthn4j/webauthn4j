package com.webauthn4j.gradle

import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.MapProperty

abstract class SecurityProviderConfiguration(val name: String) {
    /** Provider class names to register (in priority order) */
    abstract val providers: ListProperty<String>
    /** Additional security properties to set */
    abstract val securityProperties: MapProperty<String, String>
}
