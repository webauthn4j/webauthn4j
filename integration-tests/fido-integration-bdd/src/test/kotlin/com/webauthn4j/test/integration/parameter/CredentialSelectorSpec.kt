package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting.*
import com.webauthn4j.ctap.authenticator.data.settings.ResidentKeySetting
import com.webauthn4j.ctap.client.PublicKeyCredentialRequestContext
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe

@Tags("Parameter")
class CredentialSelectorSpec : BehaviorSpec({

    listOf(
        CLIENT_PLATFORM,
        AUTHENTICATOR,
    ).forEach { selectorSetting ->

        Given("two discoverable credentials with $selectorSetting credential selector") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator {
                        residentKey = ResidentKeySetting.ALWAYS
                        credentialSelector = selectorSetting
                    }
                }
                relyingParty { residentKeyRequirement = ResidentKeyRequirement.REQUIRED }
            }
            env.scenario.register()
            env.scenario.register()

            When("authenticating without allowCredentials (discoverable flow)") {
                var candidateCount = 0
                val options = env.scenario.createAuthenticationOptions(allowCredentials = null)
                val context = PublicKeyCredentialRequestContext(
                    env.clientPlatform.origin,
                    publicKeyCredentialSelectionHandler = {
                        candidateCount = it.size
                        it.first()
                    },
                    clientPINProvider = { env.clientPlatform.clientPINValue.toByteArray() }
                )
                env.clientPlatform.webAuthnClient.get(options.publicKeyCredentialRequestOptions, context)

                when (selectorSetting) {
                    CLIENT_PLATFORM -> {
                        Then("the client-side selector should receive multiple candidates") {
                            candidateCount shouldBe 2
                        }
                    }
                    AUTHENTICATOR -> {
                        Then("the authenticator should have already selected (client receives single candidate)") {
                            candidateCount shouldBe 1
                        }
                    }
                }
            }
        }
    }
})
