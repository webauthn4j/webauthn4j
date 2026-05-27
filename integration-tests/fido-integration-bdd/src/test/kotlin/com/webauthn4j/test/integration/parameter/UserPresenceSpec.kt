package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.client.exception.UPNotSupportedException
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

@Tags("Parameter")
class UserPresenceSpec : BehaviorSpec({

    Given("an authenticator with userPresence=SUPPORTED") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { userPresence = UserPresenceSetting.SUPPORTED }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("the UP flag should be set in authenticator data") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.authenticatorData.isFlagUP shouldBe true
            }

            Then("authentication should succeed with UP flag set") {
                val auth = env.scenario.authenticate()
                auth.authenticationData.authenticatorData.shouldNotBeNull()
                    .isFlagUP shouldBe true
            }
        }
    }

    Given("an authenticator with userPresence=NOT_SUPPORTED") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { userPresence = UserPresenceSetting.NOT_SUPPORTED }
            }
            relyingParty()
        }

        When("attempting to register") {
            Then("an exception should be thrown") {
                shouldThrow<UPNotSupportedException> {
                    env.scenario.register()
                }
            }
        }
    }

    // TODO: Conditional mediation requires the client to skip UP and the authenticator to
    //  return UP=false. The current webauthn4j-ctap client always requires UP support
    //  (throws UPNotSupportedException otherwise), so a true conditional mediation flow
    //  (authenticator UP=NOT_SUPPORTED + server userPresenceRequired=false) cannot be tested.
    xGiven("conditional mediation: authenticator UP=false, server accepts without UP") {
        When("registering and authenticating without user presence") {
            Then("server should accept despite UP flag being false") {}
        }
    }
})
