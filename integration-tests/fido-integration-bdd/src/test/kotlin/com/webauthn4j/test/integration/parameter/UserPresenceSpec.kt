package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserPresenceSetting.*
import com.webauthn4j.ctap.client.exception.UPNotSupportedException
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.UserNotPresentException
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe

@Tags("Parameter")
class UserPresenceSpec : BehaviorSpec({

    // --- Axis 1: RP configuration ---

    data class RPConfig(
        val conditionalMediation: Boolean,
        val userPresenceRequired: Boolean,
    ) {
        override fun toString() = "conditionalMediation=$conditionalMediation, userPresenceRequired=$userPresenceRequired"
    }

    val REQUIRE_UP      = RPConfig(conditionalMediation = false, userPresenceRequired = true)
    val DONT_REQUIRE_UP = RPConfig(conditionalMediation = false, userPresenceRequired = false)
    val CONDITIONAL     = RPConfig(conditionalMediation = true,  userPresenceRequired = false)

    // --- Axis 2: Authenticator UP capability ---

    data class AuthenticatorState(
        val setting: UserPresenceSetting,
    ) {
        override fun toString() = "$setting"
    }

    val UP_SUPPORTED     = AuthenticatorState(SUPPORTED)
    val UP_NOT_SUPPORTED = AuthenticatorState(NOT_SUPPORTED)

    // --- Matrix ---

    data class MatrixEntry(
        val rp: RPConfig,
        val auth: AuthenticatorState,
        val clientSuccess: Boolean,
        val serverSuccess: Boolean = true,
        val expectedUPFlag: Boolean? = null,
    )

    listOf(
        //          RP                Authenticator        client  server  expected UP
        MatrixEntry(REQUIRE_UP,       UP_SUPPORTED,       true,   true,   true),
        MatrixEntry(REQUIRE_UP,       UP_NOT_SUPPORTED,   false),
        MatrixEntry(DONT_REQUIRE_UP,  UP_SUPPORTED,       true,   true,   true),
        MatrixEntry(DONT_REQUIRE_UP,  UP_NOT_SUPPORTED,   false),
    ).forEach { (rp, auth, clientSuccess, serverSuccess, expectedUPFlag) ->

        Given("registration: RP $rp × authenticator $auth") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator { userPresence = auth.setting }
                }
                relyingParty { userPresenceRequired = rp.userPresenceRequired }
            }

            When("registering a credential") {
                if (!clientSuccess) {
                    Then("client-side error should be thrown") {
                        shouldThrow<UPNotSupportedException> {
                            env.scenario.relyingParty.createRegistrationOptions()
                                .clientPlatform.createCredential()
                        }
                    }
                } else if (!serverSuccess) {
                    Then("UserNotPresentException should be thrown") {
                        shouldThrow<UserNotPresentException> {
                            env.scenario.relyingParty.createRegistrationOptions()
                                .clientPlatform.createCredential()
                                .relyingParty.verify()
                        }
                    }
                } else {
                    Then("registration should succeed with UP=$expectedUPFlag") {
                        val reg = env.scenario.relyingParty.createRegistrationOptions()
                            .clientPlatform.createCredential()
                            .relyingParty.verify()
                        if (expectedUPFlag != null) {
                            reg.registrationData.attestationObject!!.authenticatorData.isFlagUP shouldBe expectedUPFlag
                        }
                    }
                }
            }
        }

        Given("authentication: RP $rp × authenticator $auth") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator { userPresence = auth.setting }
                }
                relyingParty { userPresenceRequired = rp.userPresenceRequired }
            }

            When("authenticating") {
                if (!clientSuccess) {
                    Then("registration should fail before authentication") {
                        shouldThrow<UPNotSupportedException> {
                            env.scenario.register()
                        }
                    }
                } else if (!serverSuccess) {
                    Then("UserNotPresentException should be thrown") {
                        env.scenario.register()
                        shouldThrow<UserNotPresentException> {
                            env.scenario.authenticate()
                        }
                    }
                } else {
                    Then("authentication should succeed with UP=$expectedUPFlag") {
                        env.scenario.register()
                        shouldNotThrowAny {
                            env.scenario.authenticate()
                        }
                    }
                }
            }
        }
    }

    // --- Conditional mediation: client passes up=false to authenticator ---
    // The current WebAuthnClient always requires UP support and does not support
    // conditional mediation. These tests require bypassing the client or adding
    // conditional mediation support to the test DSL.

    listOf(
        MatrixEntry(CONDITIONAL, UP_SUPPORTED, clientSuccess = true, serverSuccess = true, expectedUPFlag = false),
    ).forEach { (rp, auth, _, _, _) ->
        xGiven("registration: RP $rp × authenticator $auth") {
            When("registering with conditional mediation") {
                Then("registration should succeed with UP=false") {}
            }
        }

        xGiven("authentication: RP $rp × authenticator $auth") {
            When("authenticating with conditional mediation") {
                Then("authentication should succeed with UP=false") {}
            }
        }
    }
})
