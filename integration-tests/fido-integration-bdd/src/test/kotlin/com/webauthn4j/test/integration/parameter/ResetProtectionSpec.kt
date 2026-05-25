package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.data.settings.ResetProtectionSetting
import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.string.shouldContain

@Tags("Parameter")
class ResetProtectionSpec : BehaviorSpec({

    Given("an authenticator with resetProtection=ENABLED") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { resetProtection = ResetProtectionSetting.ENABLED }
            }
            relyingParty()
        }

        When("attempting to reset the authenticator") {
            Then("CTAP2_ERR_OPERATION_DENIED should be thrown") {
                val ex = shouldThrow<CtapErrorException> {
                    env.clientPlatform.ctapService.reset()
                }
                ex.message.shouldContain("CTAP2_ERR_OPERATION_DENIED")
            }
        }
    }

    Given("an authenticator with resetProtection=DISABLED") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { resetProtection = ResetProtectionSetting.DISABLED }
            }
            relyingParty()
        }

        When("resetting the authenticator") {
            Then("the reset should succeed without error") {
                shouldNotThrowAny { env.clientPlatform.ctapService.reset() }
            }
        }
    }
})
