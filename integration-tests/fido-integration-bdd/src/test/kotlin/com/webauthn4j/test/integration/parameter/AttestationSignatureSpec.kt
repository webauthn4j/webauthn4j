package com.webauthn4j.test.integration.parameter

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FBasicAttestationStatementProvider
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import com.webauthn4j.test.TestAttestationUtil
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier
import com.webauthn4j.verifier.exception.BadSignatureException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class AttestationSignatureSpec : BehaviorSpec({

    Given("a Packed attestation environment with signature verification") {
        val env = WebAuthnTestEnvironment.forTestsWithAttestationVerification()

        When("registering with a tampered attestation signature") {
            val credentialCreated = env.scenario.relyingParty.createRegistrationOptions()
                .clientPlatform.createCredential()

            Then("BadSignatureException should be thrown") {
                shouldThrow<BadSignatureException> {
                    credentialCreated.relyingParty.verify(
                        attestationObject = {
                            val stmt = it.attestationStatement as PackedAttestationStatement
                            val tamperedSig = ByteArray(stmt.sig.size) { i -> stmt.sig[i].toInt().inv().toByte() }
                            AttestationObject(it.authenticatorData, PackedAttestationStatement(stmt.alg, tamperedSig, stmt.x5c))
                        }
                    )
                }
            }
        }
    }

    Given("a FIDO U2F attestation environment with signature verification") {
        val privateKey = TestAttestationUtil.load2tierTestAuthenticatorAttestationPrivateKey()
        val certificate = TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate()
        val trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith2tierTestRootCACertificate()

        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = FIDOU2FBasicAttestationStatementProvider(privateKey, certificate)
                    aaguid = AAGUID.ZERO
                }
            }
            relyingParty {
                attestation = AttestationConveyancePreference.DIRECT
                webAuthnManager = WebAuthnManager(
                    listOf(FIDOU2FAttestationStatementVerifier()),
                    DefaultCertPathTrustworthinessVerifier(trustAnchorRepository),
                    DefaultSelfAttestationTrustworthinessVerifier()
                )
            }
        }

        When("registering with a tampered attestation signature") {
            val credentialCreated = env.scenario.relyingParty.createRegistrationOptions()
                .clientPlatform.createCredential()

            Then("BadSignatureException should be thrown") {
                shouldThrow<BadSignatureException> {
                    credentialCreated.relyingParty.verify(
                        attestationObject = {
                            val stmt = it.attestationStatement as FIDOU2FAttestationStatement
                            val tamperedSig = ByteArray(stmt.sig.size) { i -> stmt.sig[i].toInt().inv().toByte() }
                            AttestationObject(it.authenticatorData, FIDOU2FAttestationStatement(stmt.x5c, tamperedSig))
                        }
                    )
                }
            }
        }
    }
})
