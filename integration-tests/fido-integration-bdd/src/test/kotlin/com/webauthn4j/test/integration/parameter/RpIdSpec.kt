package com.webauthn4j.test.integration.parameter

import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.BadRpIdException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class RpIdSpec : BehaviorSpec({

    Given("a credential presented to a different RP during registration") {
        val env = WebAuthnTestEnvironment.forTestsWithoutAttestationVerification()

        When("the server verifies with a different rpId") {
            Then("BadRpIdException should be thrown") {
                shouldThrow<BadRpIdException> {
                    env.scenario.relyingParty.createRegistrationOptions()
                        .clientPlatform.createCredential()
                        .relyingParty.verify(rpId = "another.site.example.net")
                }
            }
        }
    }

    Given("a credential presented to a different RP during authentication") {
        val env = WebAuthnTestEnvironment.forTestsWithoutAttestationVerification()
        env.scenario.register()

        When("the server verifies with a different rpId") {
            Then("BadRpIdException should be thrown") {
                shouldThrow<BadRpIdException> {
                    env.scenario.relyingParty.createAuthenticationOptions()
                        .clientPlatform.getAssertion()
                        .relyingParty.verify(rpId = "another.site.example.net")
                }
            }
        }
    }
})
