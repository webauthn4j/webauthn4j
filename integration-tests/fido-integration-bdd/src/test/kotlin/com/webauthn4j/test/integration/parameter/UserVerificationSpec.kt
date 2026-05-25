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

    // ============================================================
    // Registration: RP requirement × Authenticator state matrix
    // ============================================================

    // --- Axis 1: RP requirement + server verification condition ---

    data class RPConfig(
        val requirement: UserVerificationRequirement,
        val uvRequired: Boolean,
    ) {
        override fun toString() = requirement.toString()
    }

    val REQUIRE_UV    = RPConfig(REQUIRED,    uvRequired = true)
    val PREFER_UV     = RPConfig(PREFERRED,   uvRequired = false)
    val DISCOURAGE_UV = RPConfig(DISCOURAGED, uvRequired = false)

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

    // --- Matrix: RP × Authenticator → expected result ---

    data class MatrixEntry(
        val rp: RPConfig,
        val auth: AuthenticatorState,
        val success: Boolean,
        val uvFlag: Boolean? = null,
    )

    listOf(
        //          RP               Authenticator          success  UV flag
        MatrixEntry(REQUIRE_UV,      READY_WITH_PIN,        true,    true),
        MatrixEntry(REQUIRE_UV,      READY_NO_PIN,          true,    true),
        MatrixEntry(REQUIRE_UV,      NOT_READY_SET_PIN,     true,    true),
        MatrixEntry(REQUIRE_UV,      NOT_READY_NO_PIN,      false),
        MatrixEntry(REQUIRE_UV,      NO_UV_NO_PIN,          false),
        MatrixEntry(PREFER_UV,       READY_WITH_PIN,        true,    true),
        MatrixEntry(PREFER_UV,       READY_NO_PIN,          true,    true),
        MatrixEntry(PREFER_UV,       NOT_READY_SET_PIN,     true,    true),
        MatrixEntry(PREFER_UV,       NOT_READY_NO_PIN,      true,    false),
        MatrixEntry(PREFER_UV,       NO_UV_NO_PIN,          true,    false),
        MatrixEntry(DISCOURAGE_UV,   READY_WITH_PIN,        true,    false),
        MatrixEntry(DISCOURAGE_UV,   READY_NO_PIN,          true,    false),
        MatrixEntry(DISCOURAGE_UV,   NOT_READY_SET_PIN,     true,    false),
        MatrixEntry(DISCOURAGE_UV,   NOT_READY_NO_PIN,      true,    false),
        MatrixEntry(DISCOURAGE_UV,   NO_UV_NO_PIN,          true,    false),
    ).forEach { (rp, auth, success, uvFlag) ->

        Given("RP $rp × authenticator $auth") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator { userVerification = auth.uv; clientPIN = auth.pin }
                }
                relyingParty { userVerificationRequirement = rp.requirement; userVerificationRequired = rp.uvRequired }
            }
            if (auth.setPIN) env.clientPlatform.ctapService.setPIN("clientPIN")

            When("registering a credential") {
                if (success) {
                    Then("registration should succeed") {
                        val reg = env.scenario.register()
                        if (uvFlag != null) {
                            reg.registrationData.attestationObject!!.authenticatorData.isFlagUV shouldBe uvFlag
                        }
                    }
                } else {
                    Then("an error should be thrown") {
                        shouldThrow<WebAuthnClientException> { env.scenario.register() }
                    }
                }
            }
        }
    }

    // ============================================================
    // Authentication: server UV requirement vs client UV behavior
    // ============================================================

    Given("server requires UV but client authenticates with DISCOURAGED") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform { authenticator() }
            relyingParty { userVerificationRequirement = REQUIRED; userVerificationRequired = true }
        }
        env.scenario.register()

        When("authenticating without UV while server requires it") {
            Then("UserNotVerifiedException should be thrown") {
                shouldThrow<UserNotVerifiedException> {
                    env.scenario.createAuthenticationOptions(userVerificationRequirement = DISCOURAGED)
                        .getAssertion()
                        .verifyOnServer(userVerificationRequired = true)
                }
            }
        }
    }

    Given("server does not require UV and client authenticates with DISCOURAGED") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform { authenticator() }
            relyingParty { userVerificationRequirement = DISCOURAGED; userVerificationRequired = false }
        }
        env.scenario.register()

        When("authenticating without UV") {
            Then("the server should accept the authentication") {
                shouldNotThrowAny {
                    env.scenario.createAuthenticationOptions(userVerificationRequirement = DISCOURAGED)
                        .getAssertion()
                        .verifyOnServer(userVerificationRequired = false)
                }
            }
        }
    }
})
