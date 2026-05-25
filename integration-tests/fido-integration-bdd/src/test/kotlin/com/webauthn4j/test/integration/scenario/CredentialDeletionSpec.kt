package com.webauthn4j.test.integration.scenario

import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Scenario")
class CredentialDeletionSpec : BehaviorSpec({

    Given("a registered credential that is then deleted from the server") {
        val env = WebAuthnTestEnvironment.createDefault()
        val registration = env.scenario.register()
        env.relyingParty.deleteCredential(registration.credential.rawId)

        When("attempting to authenticate") {
            Then("credential not found error should be thrown") {
                shouldThrow<IllegalStateException> {
                    env.scenario.authenticate()
                }
            }
        }
    }
})
