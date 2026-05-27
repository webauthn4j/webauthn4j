package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.BadChallengeException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class ChallengeSpec : BehaviorSpec({

    // Simulates a challenge fixation attack where the attacker uses a pre-determined
    // challenge value instead of the one issued by the server.
    val fixedChallenge = DefaultChallenge(ByteArray(32) { 0x41 })

    Given("a registration with a tampered challenge (challenge fixation attack)") {
        val env = WebAuthnTestEnvironment.createDefault()

        When("the credential is created with an attacker's fixed challenge instead of the server's") {
            val credentialCreated = env.scenario.createRegistrationOptions()
                .createCredential(overrideChallenge = fixedChallenge)

            Then("BadChallengeException should be thrown") {
                shouldThrow<BadChallengeException> {
                    credentialCreated.verifyOnServer()
                }
            }
        }
    }

    Given("an authentication with a tampered challenge (challenge fixation attack)") {
        val env = WebAuthnTestEnvironment.createDefault()
        env.scenario.register()

        When("the assertion is created with an attacker's fixed challenge instead of the server's") {
            val assertionCreated = env.scenario.createAuthenticationOptions()
                .getAssertion(overrideChallenge = fixedChallenge)

            Then("BadChallengeException should be thrown") {
                shouldThrow<BadChallengeException> {
                    assertionCreated.verifyOnServer()
                }
            }
        }
    }
})
