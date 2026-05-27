package com.webauthn4j.test.integration.scenario

import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

@Tags("Scenario")
class ClientPINManagementSpec : BehaviorSpec({

    Given("an authenticator with clientPIN already set") {
        val env = WebAuthnTestEnvironment.createDefault()
        // Explicitly set the initial PIN
        env.clientPlatform.ctapService.setPIN("clientPIN")

        When("attempting to set a new PIN without resetting") {
            Then("CTAP2_ERR_PIN_AUTH_INVALID should be thrown") {
                val ex = shouldThrow<CtapErrorException> {
                    env.clientPlatform.ctapService.setPIN("new-PIN")
                }
                ex.message.shouldContain("CTAP2_ERR_PIN_AUTH_INVALID")
            }
        }
    }

    Given("an authenticator with clientPIN set for PIN change") {
        val env = WebAuthnTestEnvironment.createDefault()
        // Explicitly set the initial PIN
        env.clientPlatform.ctapService.setPIN("clientPIN")

        When("changing the PIN with the correct current PIN") {
            Then("the PIN change should succeed") {
                shouldNotThrowAny { env.clientPlatform.ctapService.changePIN("clientPIN", "new-PIN") }
            }
        }
    }

    Given("a registered credential and then PIN is changed") {
        val env = WebAuthnTestEnvironment.createDefault()
        // Explicitly set the initial PIN before registration
        env.clientPlatform.ctapService.setPIN("clientPIN")
        env.scenario.register()

        When("changing the PIN and then authenticating") {
            env.clientPlatform.ctapService.changePIN("clientPIN", "new-PIN")

            Then("authentication should still succeed with the existing credential") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    Given("an authenticator for retry count verification") {
        val env = WebAuthnTestEnvironment.createDefault()

        When("checking the initial retry count") {
            val retries = env.clientPlatform.ctapService.getRetries()

            Then("the retry count should be the maximum") {
                retries shouldBe 8u
            }
        }
    }
})
