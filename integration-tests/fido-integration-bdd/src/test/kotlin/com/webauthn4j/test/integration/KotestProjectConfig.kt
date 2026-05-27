package com.webauthn4j.test.integration

import com.webauthn4j.test.integration.support.BddHtmlReporter
import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.extensions.Extension

class KotestProjectConfig : AbstractProjectConfig() {
    override fun extensions(): List<Extension> = listOf(
        BddHtmlReporter(),
    )
}
