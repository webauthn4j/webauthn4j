package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.client.Origin
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.BadOriginException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class OriginSpec : BehaviorSpec({

    Given("a registration from a malicious origin") {
        val env = WebAuthnTestEnvironment.createDefault()

        When("the credential is created from a different origin than the server expects") {
            Then("BadOriginException should be thrown") {
                shouldThrow<BadOriginException> {
                    env.scenario.createRegistrationOptions()
                        .createCredential(overrideOrigin = Origin("https://evil.example.com"))
                        .verifyOnServer()
                }
            }
        }
    }

    Given("an authentication from a malicious origin") {
        val env = WebAuthnTestEnvironment.createDefault()
        env.scenario.register()

        When("the assertion is created from a different origin than the server expects") {
            Then("BadOriginException should be thrown") {
                shouldThrow<BadOriginException> {
                    env.scenario.createAuthenticationOptions()
                        .getAssertion(overrideOrigin = Origin("https://evil.example.com"))
                        .verifyOnServer()
                }
            }
        }
    }
})
