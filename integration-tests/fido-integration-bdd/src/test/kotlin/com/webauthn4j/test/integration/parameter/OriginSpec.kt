package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.client.Origin
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.BadOriginException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class OriginSpec : BehaviorSpec({

    Given("a default test environment") {
        val env = WebAuthnTestEnvironment.forTestsWithoutAttestationVerification()

        When("registering from a different origin than the server expects") {
            Then("BadOriginException should be thrown") {
                shouldThrow<BadOriginException> {
                    env.scenario.server.createRegistrationOptions()
                        .clientPlatform.createCredential(origin = Origin("https://evil.example.com"))
                        .server.verify()
                }
            }
        }
    }

    Given("a registered credential") {
        val env = WebAuthnTestEnvironment.forTestsWithoutAttestationVerification()
        env.scenario.register()

        When("authenticating from a different origin than the server expects") {
            Then("BadOriginException should be thrown") {
                shouldThrow<BadOriginException> {
                    env.scenario.server.createAuthenticationOptions()
                        .clientPlatform.getAssertion(origin = Origin("https://evil.example.com"))
                        .server.verify()
                }
            }
        }
    }
})
