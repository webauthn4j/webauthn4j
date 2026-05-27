package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FBasicAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.NoneAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.PackedBasicAttestationStatementProvider
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import com.webauthn4j.test.TestAttestationUtil
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

@Tags("Parameter")
class AttestationFormatSpec : BehaviorSpec({

    Given("a Packed attestation authenticator") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = PackedBasicAttestationStatementProvider.createWithDemoAttestationKey()
                }
            }
            relyingParty { attestation = AttestationConveyancePreference.DIRECT }
        }

        When("registering a credential") {
            Then("the attestation statement should be PackedAttestationStatement with AT flag set") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.attestationStatement.shouldBeInstanceOf<PackedAttestationStatement>()
                reg.registrationData.attestationObject!!.authenticatorData.isFlagAT shouldBe true
            }

            Then("authentication should succeed") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    Given("a FIDO U2F attestation authenticator") {
        val privateKey = TestAttestationUtil.load2tierTestAuthenticatorAttestationPrivateKey()
        val certificate = TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate()

        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = FIDOU2FBasicAttestationStatementProvider(privateKey, certificate)
                    aaguid = AAGUID.ZERO
                }
            }
            relyingParty { attestation = AttestationConveyancePreference.DIRECT }
        }

        When("registering a credential") {
            Then("the attestation statement should be FIDOU2FAttestationStatement") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.attestationStatement.shouldBeInstanceOf<FIDOU2FAttestationStatement>()
            }

            Then("authentication should succeed") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    Given("a None attestation authenticator") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = NoneAttestationStatementProvider()
                    aaguid = AAGUID.ZERO
                }
            }
            relyingParty()
        }

        When("registering a credential") {
            Then("the attestation statement should be NoneAttestationStatement") {
                val reg = env.scenario.register()
                reg.registrationData.attestationObject!!.attestationStatement.shouldBeInstanceOf<NoneAttestationStatement>()
            }

            Then("authentication should succeed") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    // --- Formats not yet supported by webauthn4j-ctap authenticator emulator ---

    xGiven("a TPM attestation authenticator") {
        // TODO: Requires TPM AttestationStatementProvider implementation
        When("registering a credential") {
            Then("the attestation statement should be TPMAttestationStatement") {}
        }
    }

    xGiven("an Android Key attestation authenticator") {
        // TODO: Requires AndroidKey AttestationStatementProvider implementation
        When("registering a credential") {
            Then("the attestation statement should be AndroidKeyAttestationStatement") {}
        }
    }

    xGiven("an Android SafetyNet attestation authenticator") {
        // TODO: Requires AndroidSafetyNet AttestationStatementProvider implementation
        When("registering a credential") {
            Then("the attestation statement should be AndroidSafetyNetAttestationStatement") {}
        }
    }

    xGiven("an Apple Anonymous attestation authenticator") {
        // TODO: Requires AppleAnonymous AttestationStatementProvider implementation
        When("registering a credential") {
            Then("the attestation statement should be AppleAnonymousAttestationStatement") {}
        }
    }
})
