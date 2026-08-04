package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.util.MessageDigestUtil
import com.webauthn4j.verifier.exception.BadRpIdException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class AuthenticatorDataSpec : BehaviorSpec({

    Given("a registered credential") {
        val env = WebAuthnTestEnvironment.createDefault()
        env.scenario.register()

        When("authenticating with rpIdHash replaced to a different RP") {
            val evilRpIdHash = MessageDigestUtil.createSHA256()
                .digest("evil.example.com".toByteArray())

            val assertionCreated = env.scenario.server.createAuthenticationOptions()
                .clientPlatform.getAssertion()

            Then("BadRpIdException should be thrown") {
                shouldThrow<BadRpIdException> {
                    assertionCreated.server.verify(
                        authenticatorData = {
                            AuthenticatorData(evilRpIdHash, it.flags, it.signCount)
                        }
                    )
                }
            }
        }
    }
})
