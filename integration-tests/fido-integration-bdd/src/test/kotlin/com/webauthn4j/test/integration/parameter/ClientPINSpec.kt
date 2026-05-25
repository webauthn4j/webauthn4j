package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe

@Tags("Parameter")
class ClientPINSpec : BehaviorSpec({

    Given("clientPIN ENABLED with UV REQUIRED") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    clientPIN = ClientPINSetting.ENABLED
                    userVerification = UserVerificationSetting.READY
                }
            }
            relyingParty {
                userVerificationRequirement = UserVerificationRequirement.REQUIRED
                userVerificationRequired = true
            }
        }

        When("registering a credential") {
            val reg = env.scenario.register()

            Then("registration should succeed with UV flag set") {
                reg.registrationData.attestationObject!!.authenticatorData.isFlagUV shouldBe true
            }

            Then("authentication should succeed") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    Given("clientPIN DISABLED with UV READY") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    clientPIN = ClientPINSetting.DISABLED
                    userVerification = UserVerificationSetting.READY
                }
            }
            relyingParty {
                userVerificationRequirement = UserVerificationRequirement.REQUIRED
                userVerificationRequired = true
            }
        }

        When("registering a credential") {
            val reg = env.scenario.register()

            Then("registration should succeed with UV flag set (built-in UV, no PIN needed)") {
                reg.registrationData.attestationObject!!.authenticatorData.isFlagUV shouldBe true
            }

            Then("authentication should succeed") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    Given("clientPIN ENABLED with UV NOT_READY") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    clientPIN = ClientPINSetting.ENABLED
                    userVerification = UserVerificationSetting.NOT_READY
                }
            }
            relyingParty {
                userVerificationRequirement = UserVerificationRequirement.REQUIRED
                userVerificationRequired = true
            }
        }

        When("setting PIN and registering") {
            env.clientPlatform.ctapService.setPIN("clientPIN")
            val reg = env.scenario.register()

            Then("registration should succeed via PIN-based UV fallback") {
                reg.registrationData.attestationObject!!.authenticatorData.isFlagUV shouldBe true
            }
        }
    }
})
