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
        val env = WebAuthnTestEnvironment.forTestsWithoutAttestationVerification()

        When("the credential is created with an attacker's fixed challenge instead of the server's") {
            val credentialCreated = env.scenario.server.createRegistrationOptions()
                .clientPlatform.createCredential(challenge = fixedChallenge)

            Then("BadChallengeException should be thrown") {
                shouldThrow<BadChallengeException> {
                    credentialCreated.server.verify()
                }
            }
        }
    }

    Given("an authentication with a tampered challenge (challenge fixation attack)") {
        val env = WebAuthnTestEnvironment.forTestsWithoutAttestationVerification()
        env.scenario.register()

        When("the assertion is created with an attacker's fixed challenge instead of the server's") {
            val assertionCreated = env.scenario.server.createAuthenticationOptions()
                .clientPlatform.getAssertion(challenge = fixedChallenge)

            Then("BadChallengeException should be thrown") {
                shouldThrow<BadChallengeException> {
                    assertionCreated.server.verify()
                }
            }
        }
    }
})
