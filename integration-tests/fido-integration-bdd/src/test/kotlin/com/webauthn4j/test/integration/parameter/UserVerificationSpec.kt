package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting.DISABLED
import com.webauthn4j.ctap.authenticator.data.settings.ClientPINSetting.ENABLED
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting
import com.webauthn4j.ctap.authenticator.data.settings.UserVerificationSetting.*
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.UserVerificationRequirement.*
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.UserNotVerifiedException
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe

@Tags("Parameter")
class UserVerificationSpec : BehaviorSpec({

    // --- Axis 1: RP client-facing requirement + server-side verification ---

    data class RPConfig(
        val requirement: UserVerificationRequirement,
        val userVerificationRequired: Boolean,
    ) {
        override fun toString() = "$requirement, userVerificationRequired=$userVerificationRequired"
    }

    val REQUIRE_UV             = RPConfig(REQUIRED,    userVerificationRequired = true)
    val PREFER_UV              = RPConfig(PREFERRED,   userVerificationRequired = false)
    val DISCOURAGE_UV          = RPConfig(DISCOURAGED, userVerificationRequired = false)
    val DISCOURAGE_BUT_REQUIRE = RPConfig(DISCOURAGED, userVerificationRequired = true)

    // --- Axis 2: Authenticator UV capability + ClientPIN state ---

    data class AuthenticatorState(
        val uv: UserVerificationSetting,
        val pin: ClientPINSetting,
        val setPIN: Boolean = false,
    ) {
        override fun toString() = if (setPIN) "$uv, PIN $pin (+setPIN)" else "$uv, PIN $pin"
    }

    val READY_WITH_PIN    = AuthenticatorState(READY,         ENABLED)
    val READY_NO_PIN      = AuthenticatorState(READY,         DISABLED)
    val NOT_READY_SET_PIN = AuthenticatorState(NOT_READY,     ENABLED,  setPIN = true)
    val NOT_READY_NO_PIN  = AuthenticatorState(NOT_READY,     DISABLED)
    val NO_UV_NO_PIN      = AuthenticatorState(NOT_SUPPORTED, DISABLED)

    // ============================================================
    // Registration
    // ============================================================

    data class RegistrationEntry(
        val rp: RPConfig,
        val auth: AuthenticatorState,
        val clientSuccess: Boolean,
        val serverSuccess: Boolean = true,
        val uvFlag: Boolean? = null,
    )

    listOf(
        //                    RP                         Authenticator         client  server  UV flag
        RegistrationEntry(REQUIRE_UV,                READY_WITH_PIN,       true,   true,   true),
        RegistrationEntry(REQUIRE_UV,                READY_NO_PIN,         true,   true,   true),
        RegistrationEntry(REQUIRE_UV,                NOT_READY_SET_PIN,    true,   true,   true),
        RegistrationEntry(REQUIRE_UV,                NOT_READY_NO_PIN,     false),
        RegistrationEntry(REQUIRE_UV,                NO_UV_NO_PIN,         false),
        RegistrationEntry(PREFER_UV,                 READY_WITH_PIN,       true,   true,   true),
        RegistrationEntry(PREFER_UV,                 READY_NO_PIN,         true,   true,   true),
        RegistrationEntry(PREFER_UV,                 NOT_READY_SET_PIN,    true,   true,   true),
        RegistrationEntry(PREFER_UV,                 NOT_READY_NO_PIN,     true,   true,   false),
        RegistrationEntry(PREFER_UV,                 NO_UV_NO_PIN,         true,   true,   false),
        RegistrationEntry(DISCOURAGE_UV,             READY_WITH_PIN,       true,   true,   false),
        RegistrationEntry(DISCOURAGE_UV,             READY_NO_PIN,         true,   true,   false),
        RegistrationEntry(DISCOURAGE_UV,             NOT_READY_SET_PIN,    true,   true,   false),
        RegistrationEntry(DISCOURAGE_UV,             NOT_READY_NO_PIN,     true,   true,   false),
        RegistrationEntry(DISCOURAGE_UV,             NO_UV_NO_PIN,         true,   true,   false),
        RegistrationEntry(DISCOURAGE_BUT_REQUIRE,    READY_WITH_PIN,       true,   false,  false),
        RegistrationEntry(DISCOURAGE_BUT_REQUIRE,    READY_NO_PIN,         true,   false,  false),
        RegistrationEntry(DISCOURAGE_BUT_REQUIRE,    NOT_READY_SET_PIN,    true,   false,  false),
        RegistrationEntry(DISCOURAGE_BUT_REQUIRE,    NOT_READY_NO_PIN,     true,   false,  false),
        RegistrationEntry(DISCOURAGE_BUT_REQUIRE,    NO_UV_NO_PIN,         true,   false,  false),
    ).forEach { (rp, auth, clientSuccess, serverSuccess, uvFlag) ->

        Given("registration: RP $rp × authenticator $auth") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator { userVerification = auth.uv; clientPIN = auth.pin }
                }
                relyingParty { userVerificationRequirement = rp.requirement; userVerificationRequired = rp.userVerificationRequired }
            }
            if (auth.setPIN) env.clientPlatform.ctapService.setPIN("clientPIN")

            When("registering a credential") {
                if (!clientSuccess) {
                    Then("client-side error should be thrown") {
                        shouldThrow<WebAuthnClientException> {
                            env.scenario.relyingParty.createRegistrationOptions()
                                .clientPlatform.createCredential()
                        }
                    }
                } else if (!serverSuccess) {
                    Then("UserNotVerifiedException should be thrown") {
                        shouldThrow<UserNotVerifiedException> {
                            env.scenario.relyingParty.createRegistrationOptions()
                                .clientPlatform.createCredential()
                                .relyingParty.verify()
                        }
                    }
                } else {
                    Then("registration should succeed") {
                        val reg = env.scenario.relyingParty.createRegistrationOptions()
                            .clientPlatform.createCredential()
                            .relyingParty.verify()
                        if (uvFlag != null) {
                            reg.registrationData.attestationObject!!.authenticatorData.isFlagUV shouldBe uvFlag
                        }
                    }
                }
            }
        }
    }

    // ============================================================
    // Authentication
    // ============================================================

    data class AuthenticationEntry(
        val rp: RPConfig,
        val auth: AuthenticatorState,
        val clientSuccess: Boolean,
        val serverSuccess: Boolean = true,
    )

    listOf(
        //                       RP                         Authenticator         client  server
        AuthenticationEntry(REQUIRE_UV,                READY_WITH_PIN,       true,   true),
        AuthenticationEntry(REQUIRE_UV,                READY_NO_PIN,         true,   true),
        AuthenticationEntry(REQUIRE_UV,                NOT_READY_SET_PIN,    true,   true),
        AuthenticationEntry(REQUIRE_UV,                NOT_READY_NO_PIN,     false),
        AuthenticationEntry(REQUIRE_UV,                NO_UV_NO_PIN,         false),
        AuthenticationEntry(PREFER_UV,                 READY_WITH_PIN,       true,   true),
        AuthenticationEntry(PREFER_UV,                 READY_NO_PIN,         true,   true),
        AuthenticationEntry(PREFER_UV,                 NOT_READY_SET_PIN,    true,   true),
        AuthenticationEntry(PREFER_UV,                 NOT_READY_NO_PIN,     true,   true),
        AuthenticationEntry(PREFER_UV,                 NO_UV_NO_PIN,         true,   true),
        AuthenticationEntry(DISCOURAGE_UV,             READY_WITH_PIN,       true,   true),
        AuthenticationEntry(DISCOURAGE_UV,             READY_NO_PIN,         true,   true),
        AuthenticationEntry(DISCOURAGE_UV,             NOT_READY_SET_PIN,    true,   true),
        AuthenticationEntry(DISCOURAGE_UV,             NOT_READY_NO_PIN,     true,   true),
        AuthenticationEntry(DISCOURAGE_UV,             NO_UV_NO_PIN,         true,   true),
        AuthenticationEntry(DISCOURAGE_BUT_REQUIRE,    READY_WITH_PIN,       true,   false),
        AuthenticationEntry(DISCOURAGE_BUT_REQUIRE,    READY_NO_PIN,         true,   false),
        AuthenticationEntry(DISCOURAGE_BUT_REQUIRE,    NOT_READY_SET_PIN,    true,   false),
        AuthenticationEntry(DISCOURAGE_BUT_REQUIRE,    NOT_READY_NO_PIN,     true,   false),
        AuthenticationEntry(DISCOURAGE_BUT_REQUIRE,    NO_UV_NO_PIN,         true,   false),
    ).forEach { (rp, auth, clientSuccess, serverSuccess) ->

        Given("authentication: RP $rp × authenticator $auth") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator { userVerification = auth.uv; clientPIN = auth.pin }
                }
                relyingParty { userVerificationRequirement = rp.requirement; userVerificationRequired = false }
            }
            if (auth.setPIN) env.clientPlatform.ctapService.setPIN("clientPIN")

            When("authenticating") {
                if (!clientSuccess) {
                    Then("registration should fail before authentication") {
                        shouldThrow<WebAuthnClientException> {
                            env.scenario.register()
                        }
                    }
                } else {
                    env.scenario.register()

                    if (!serverSuccess) {
                        Then("UserNotVerifiedException should be thrown") {
                            shouldThrow<UserNotVerifiedException> {
                                env.scenario.relyingParty.createAuthenticationOptions(userVerificationRequirement = rp.requirement)
                                    .clientPlatform.getAssertion()
                                    .relyingParty.verify(userVerificationRequired = rp.userVerificationRequired)
                            }
                        }
                    } else {
                        Then("authentication should succeed") {
                            shouldNotThrowAny {
                                env.scenario.relyingParty.createAuthenticationOptions(userVerificationRequirement = rp.requirement)
                                    .clientPlatform.getAssertion()
                                    .relyingParty.verify(userVerificationRequired = rp.userVerificationRequired)
                            }
                        }
                    }
                }
            }
        }
    }
})
