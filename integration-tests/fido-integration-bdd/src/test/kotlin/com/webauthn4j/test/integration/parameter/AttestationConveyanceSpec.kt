package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.types.shouldBeInstanceOf

@Tags("Parameter")
class AttestationConveyanceSpec : BehaviorSpec({

    Given("attestation conveyance preference is DIRECT") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform { authenticator() }
            relyingParty { attestation = AttestationConveyancePreference.DIRECT }
        }

        When("registering with a Packed authenticator") {
            Then("the attestation statement should be preserved as PackedAttestationStatement") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.attestationStatement.shouldBeInstanceOf<PackedAttestationStatement>()
            }
        }
    }

    Given("attestation conveyance preference is NONE") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform { authenticator() }
            relyingParty { attestation = AttestationConveyancePreference.NONE }
        }

        When("registering with a Packed authenticator") {
            Then("the attestation statement should be replaced with NoneAttestationStatement") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.attestationStatement.shouldBeInstanceOf<NoneAttestationStatement>()
            }
        }
    }

    // TODO: The current webauthn4j-ctap client does not perform INDIRECT anonymization,
    //  so the attestation passes through as PackedAttestationStatement.
    //  If the client implemented INDIRECT handling, this would become NoneAttestationStatement
    //  or an anonymized statement.
    Given("attestation conveyance preference is INDIRECT") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform { authenticator() }
            relyingParty { attestation = AttestationConveyancePreference.INDIRECT }
        }

        When("registering with a Packed authenticator") {
            Then("the attestation statement should pass through as PackedAttestationStatement") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.attestationStatement.shouldBeInstanceOf<PackedAttestationStatement>()
            }
        }
    }

    // ENTERPRISE: Per spec, the client should send attestation with uniquely identifying
    // information for enterprise deployments. The current webauthn4j-ctap client/authenticator
    // does not implement enterprise attestation, so the attestation passes through as a
    // regular PackedAttestationStatement. If enterprise attestation were supported, the
    // attestation statement would contain enterprise-specific identifying information.
    Given("attestation conveyance preference is ENTERPRISE") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform { authenticator() }
            relyingParty { attestation = AttestationConveyancePreference.ENTERPRISE }
        }

        When("registering with a Packed authenticator") {
            Then("the attestation statement should pass through as PackedAttestationStatement") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.attestationStatement.shouldBeInstanceOf<PackedAttestationStatement>()
            }
        }
    }
})
