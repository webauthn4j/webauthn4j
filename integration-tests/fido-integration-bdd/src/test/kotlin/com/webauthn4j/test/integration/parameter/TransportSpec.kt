package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder

@Tags("Parameter")
class TransportSpec : BehaviorSpec({

    Given("an authenticator with transports={INTERNAL}") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { transports = setOf(AuthenticatorTransport.INTERNAL) }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("the registration response should contain INTERNAL transport") {
                val reg = env.scenario.register()
                reg.credential.response!!.transports.shouldContainExactlyInAnyOrder(
                    AuthenticatorTransport.INTERNAL
                )
            }

            Then("the credential record should store the transport") {
                val reg = env.scenario.register()
                reg.credentialRecord.transports!!.shouldContainExactlyInAnyOrder(
                    AuthenticatorTransport.INTERNAL
                )
            }
        }
    }

    Given("an authenticator with transports={USB, NFC}") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { transports = setOf(AuthenticatorTransport.USB, AuthenticatorTransport.NFC) }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("the registration response should contain both transports") {
                val reg = env.scenario.register()
                reg.credential.response!!.transports.shouldContainExactlyInAnyOrder(
                    AuthenticatorTransport.USB, AuthenticatorTransport.NFC
                )
            }
        }
    }

    Given("an authenticator with transports={BLE}") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { transports = setOf(AuthenticatorTransport.BLE) }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("the registration response should contain BLE transport") {
                val reg = env.scenario.register()
                reg.credential.response!!.transports.shouldContainExactlyInAnyOrder(
                    AuthenticatorTransport.BLE
                )
            }
        }
    }

    Given("an authenticator with transports={HYBRID}") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { transports = setOf(AuthenticatorTransport.HYBRID) }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("the registration response should contain HYBRID transport") {
                val reg = env.scenario.register()
                reg.credential.response!!.transports.shouldContainExactlyInAnyOrder(
                    AuthenticatorTransport.HYBRID
                )
            }
        }
    }

    Given("an authenticator with transports={SMART_CARD}") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator { transports = setOf(AuthenticatorTransport.SMART_CARD) }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("the registration response should contain SMART_CARD transport") {
                val reg = env.scenario.register()
                reg.credential.response!!.transports.shouldContainExactlyInAnyOrder(
                    AuthenticatorTransport.SMART_CARD
                )
            }
        }
    }

    Given("an authenticator with default transports (USB)") {
        val env = WebAuthnTestEnvironment.createDefault()

        When("registering a credential") {
            Then("the registration response should contain USB transport") {
                val reg = env.scenario.register()
                reg.credential.response!!.transports.shouldContainExactlyInAnyOrder(
                    AuthenticatorTransport.USB
                )
            }
        }
    }
})
