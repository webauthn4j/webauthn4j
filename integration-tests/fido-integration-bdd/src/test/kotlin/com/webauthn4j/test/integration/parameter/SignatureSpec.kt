package com.webauthn4j.test.integration.parameter

import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.BadSignatureException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class SignatureSpec : BehaviorSpec({

    Given("a registered credential") {
        val env = WebAuthnTestEnvironment.createDefault()
        env.scenario.register()

        When("authenticating with a tampered signature (same length, incorrect value)") {
            val assertionCreated = env.scenario.server.createAuthenticationOptions()
                .clientPlatform.getAssertion()
            val realSignature = assertionCreated.credential.response!!.signature
            val tamperedSignature = ByteArray(realSignature.size) { i -> realSignature[i].toInt().inv().toByte() }

            Then("BadSignatureException should be thrown") {
                shouldThrow<BadSignatureException> {
                    assertionCreated.server.verify(signature = tamperedSignature)
                }
            }
        }

        When("authenticating with a truncated signature (first half only)") {
            val assertionCreated = env.scenario.server.createAuthenticationOptions()
                .clientPlatform.getAssertion()
            val realSignature = assertionCreated.credential.response!!.signature
            val truncatedSignature = realSignature.copyOfRange(0, realSignature.size / 2)

            Then("BadSignatureException should be thrown") {
                shouldThrow<BadSignatureException> {
                    assertionCreated.server.verify(signature = truncatedSignature)
                }
            }
        }
    }
})
