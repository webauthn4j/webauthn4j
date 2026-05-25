package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting.*
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.data.ResidentKeyRequirement.*
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.string.shouldContain

private enum class ResidentKeyResult { DISCOVERABLE, NON_DISCOVERABLE, ERROR }

@Tags("Parameter")
class ResidentKeySpec : BehaviorSpec({

    // ============================================================
    // RP requirement × Authenticator setting matrix
    // ============================================================

    data class MatrixEntry(
        val rpRequirement: ResidentKeyRequirement,
        val authSetting: ResidentKeySetting,
        val expected: ResidentKeyResult,
    )

    listOf(
        //          RP requirement  Auth setting    expected result
        MatrixEntry(REQUIRED,       ALWAYS,         ResidentKeyResult.DISCOVERABLE),
        MatrixEntry(REQUIRED,       IF_REQUIRED,    ResidentKeyResult.DISCOVERABLE),
        MatrixEntry(REQUIRED,       NEVER,          ResidentKeyResult.ERROR),
        MatrixEntry(PREFERRED,      ALWAYS,         ResidentKeyResult.DISCOVERABLE),
        MatrixEntry(PREFERRED,      IF_REQUIRED,    ResidentKeyResult.NON_DISCOVERABLE),
        MatrixEntry(DISCOURAGED,    ALWAYS,         ResidentKeyResult.DISCOVERABLE),
    ).forEach { (rpRequirement, authSetting, expected) ->

        Given("RP $rpRequirement × authenticator $authSetting") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator { residentKey = authSetting }
                }
                relyingParty { residentKeyRequirement = rpRequirement }
            }

            when (expected) {
                ResidentKeyResult.DISCOVERABLE -> {
                    When("registering a credential") {
                        Then("a discoverable credential should be created (no allowCredentials needed)") {
                            env.scenario.register()
                            shouldNotThrowAny { env.scenario.authenticate() }
                        }
                    }
                }
                ResidentKeyResult.NON_DISCOVERABLE -> {
                    When("registering a credential") {
                        Then("a non-discoverable credential should be created (requires allowCredentials)") {
                            val reg = env.scenario.register()
                            val allowCredentials = listOf(
                                PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, reg.credential.rawId, null)
                            )
                            shouldNotThrowAny {
                                env.scenario.createAuthenticationOptions(allowCredentials = allowCredentials)
                                    .getAssertion()
                                    .verifyOnServer()
                            }
                        }
                    }
                }
                ResidentKeyResult.ERROR -> {
                    When("attempting to register") {
                        Then("WebAuthnClientException should be thrown") {
                            val ex = shouldThrow<WebAuthnClientException> { env.scenario.register() }
                            ex.message.shouldContain("Matching authenticator doesn't exist")
                        }
                    }
                }
            }
        }
    }

    // --- Cases not yet supported by webauthn4j-ctap authenticator emulator (CTAP1_ERR_OTHER) ---

    xGiven("RP PREFERRED × authenticator NEVER → NON_DISCOVERABLE") {
        // TODO: Authenticator emulator fails with CTAP1_ERR_OTHER for NEVER setting with non-required rk
        When("registering a credential") {
            Then("a non-discoverable credential should be created") {}
        }
    }

    xGiven("RP DISCOURAGED × authenticator IF_REQUIRED → NON_DISCOVERABLE") {
        // TODO: Authenticator emulator fails with CTAP1_ERR_OTHER for DISCOURAGED requirement
        When("registering a credential") {
            Then("a non-discoverable credential should be created") {}
        }
    }

    xGiven("RP DISCOURAGED × authenticator NEVER → NON_DISCOVERABLE") {
        // TODO: Authenticator emulator fails with CTAP1_ERR_OTHER for NEVER setting with DISCOURAGED
        When("registering a credential") {
            Then("a non-discoverable credential should be created") {}
        }
    }

    // TODO: RP null (unspecified) x authenticator IF_REQUIRED
    //  The test client (webauthn4j-ctap WebAuthnClient) does not accept null residentKeyRequirement.
})
