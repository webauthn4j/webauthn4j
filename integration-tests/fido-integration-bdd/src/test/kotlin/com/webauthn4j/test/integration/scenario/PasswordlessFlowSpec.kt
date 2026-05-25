package com.webauthn4j.test.integration.scenario

import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Scenario")
class PasswordlessFlowSpec : BehaviorSpec({

    Given("a relying party requiring resident key") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { residentKey = ResidentKeySetting.ALWAYS }
            }
            relyingParty { residentKeyRequirement = ResidentKeyRequirement.REQUIRED }
        }

        When("a user registers a credential") {
            env.scenario.register()

            And("the user authenticates without providing credential ID") {
                Then("the authentication should succeed") {
                    shouldNotThrowAny { env.scenario.authenticate() }
                }
            }
        }
    }
})
