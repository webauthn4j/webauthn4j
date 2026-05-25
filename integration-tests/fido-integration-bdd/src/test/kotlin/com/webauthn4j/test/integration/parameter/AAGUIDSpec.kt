package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.util.*

@Tags("Parameter")
class AAGUIDSpec : BehaviorSpec({

    Given("an authenticator with a custom AAGUID") {
        val customAaguid = AAGUID(UUID.randomUUID())
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { aaguid = customAaguid }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("the attested credential data should contain the custom AAGUID") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.authenticatorData.attestedCredentialData.shouldNotBeNull()
                    .aaguid shouldBe customAaguid
            }
        }
    }
})
