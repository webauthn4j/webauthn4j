package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.data.settings.AttachmentSetting
import com.webauthn4j.ctap.client.exception.WebAuthnClientException
import com.webauthn4j.data.AuthenticatorAttachment
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.string.shouldContain

@Tags("Parameter")
class AttachmentSpec : BehaviorSpec({

    Given("a PLATFORM authenticator and RP requests PLATFORM attachment") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { attachment = AttachmentSetting.PLATFORM }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("registration should succeed") {
                env.scenario.createRegistrationOptions(
                    authenticatorAttachment = AuthenticatorAttachment.PLATFORM
                ).createCredential().verifyOnServer()
            }
        }
    }

    Given("a CROSS_PLATFORM authenticator and RP requests PLATFORM attachment") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { attachment = AttachmentSetting.CROSS_PLATFORM }
            }
            relyingParty()
        }

        When("attempting to register") {
            Then("WebAuthnClientException should be thrown") {
                val ex = shouldThrow<WebAuthnClientException> {
                    env.scenario.createRegistrationOptions(
                        authenticatorAttachment = AuthenticatorAttachment.PLATFORM
                    ).createCredential().verifyOnServer()
                }
                ex.message.shouldContain("Matching authenticator doesn't exist")
            }
        }
    }

    Given("a PLATFORM authenticator and RP requests CROSS_PLATFORM attachment") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { attachment = AttachmentSetting.PLATFORM }
            }
            relyingParty()
        }

        When("attempting to register") {
            Then("WebAuthnClientException should be thrown") {
                val ex = shouldThrow<WebAuthnClientException> {
                    env.scenario.createRegistrationOptions(
                        authenticatorAttachment = AuthenticatorAttachment.CROSS_PLATFORM
                    ).createCredential().verifyOnServer()
                }
                ex.message.shouldContain("Matching authenticator doesn't exist")
            }
        }
    }

    Given("a CROSS_PLATFORM authenticator and RP requests CROSS_PLATFORM attachment") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { attachment = AttachmentSetting.CROSS_PLATFORM }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("registration should succeed") {
                env.scenario.createRegistrationOptions(
                    authenticatorAttachment = AuthenticatorAttachment.CROSS_PLATFORM
                ).createCredential().verifyOnServer()
            }
        }
    }

    Given("both PLATFORM and CROSS_PLATFORM authenticators with no attachment preference") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { attachment = AttachmentSetting.PLATFORM }
                authenticator { attachment = AttachmentSetting.CROSS_PLATFORM }
            }
            relyingParty()
        }

        When("registering without attachment preference") {
            Then("registration should succeed") {
                env.scenario.register()
            }
        }
    }
})
