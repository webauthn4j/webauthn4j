package com.webauthn4j.gradle

import org.gradle.api.NamedDomainObjectContainer

abstract class TestWithSecurityProviderExtension {
    abstract val configurations: NamedDomainObjectContainer<SecurityProviderConfiguration>
}
