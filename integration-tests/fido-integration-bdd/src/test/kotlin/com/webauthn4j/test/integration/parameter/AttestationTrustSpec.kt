package com.webauthn4j.test.integration.parameter

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FBasicAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.NoneAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.PackedBasicAttestationStatementProvider
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.test.TestAttestationUtil
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier
import com.webauthn4j.verifier.exception.BadAttestationStatementException
import com.webauthn4j.verifier.exception.CertificateException
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import java.security.KeyPair

@Tags("Parameter")
class AttestationTrustSpec : BehaviorSpec({

    Given("server configured with trusted root CA and Packed attestation authenticator") {
        val attestationKeyPair = KeyPair(
            TestAttestationUtil.load3tierTestAuthenticatorAttestationPublicKey(),
            TestAttestationUtil.load3tierTestAuthenticatorAttestationPrivateKey()
        )
        val intermediateCAPrivateKey = TestAttestationUtil.load3tierTestIntermediateCAPrivateKey()
        val intermediateCACert = TestAttestationUtil.load3tierTestIntermediateCACertificate()
        val trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate()

        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = PackedBasicAttestationStatementProvider(
                        "CN=Test Authenticator, OU=Authenticator Attestation, O=Test, C=US",
                        attestationKeyPair, intermediateCAPrivateKey,
                        SignatureAlgorithm.ES256, listOf(intermediateCACert), ObjectConverter()
                    )
                }
            }
            relyingParty {
                attestation = AttestationConveyancePreference.DIRECT
                webAuthnManager = WebAuthnManager(
                    listOf(PackedAttestationStatementVerifier()),
                    DefaultCertPathTrustworthinessVerifier(trustAnchorRepository),
                    DefaultSelfAttestationTrustworthinessVerifier()
                )
            }
        }

        When("registering a credential with a certificate chaining to the trusted root") {
            Then("the server should accept the attestation") {
                env.scenario.register()
            }

            Then("authentication should succeed") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    Given("server configured with a different trust anchor than the authenticator's certificate") {
        val wrongTrustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith2tierTestRootCACertificate()
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = PackedBasicAttestationStatementProvider.createWithDemoAttestationKey()
                }
            }
            relyingParty {
                attestation = AttestationConveyancePreference.DIRECT
                webAuthnManager = WebAuthnManager(
                    listOf(PackedAttestationStatementVerifier()),
                    DefaultCertPathTrustworthinessVerifier(wrongTrustAnchorRepository),
                    DefaultSelfAttestationTrustworthinessVerifier()
                )
            }
        }

        When("registering a credential with a certificate NOT chaining to the trusted root") {
            Then("the server should reject the attestation") {
                shouldThrow<CertificateException> { env.scenario.register() }
            }
        }
    }

    Given("server configured with trusted root CA and FIDO U2F attestation authenticator") {
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

        When("registering a credential with a certificate chaining to the trusted root") {
            Then("the server should accept the attestation") {
                env.scenario.register()
            }

            Then("authentication should succeed") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    Given("server configured with wrong trust anchor and FIDO U2F attestation authenticator") {
        val privateKey = TestAttestationUtil.load2tierTestAuthenticatorAttestationPrivateKey()
        val certificate = TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate()
        val wrongTrustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate()

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
                    DefaultCertPathTrustworthinessVerifier(wrongTrustAnchorRepository),
                    DefaultSelfAttestationTrustworthinessVerifier()
                )
            }
        }

        When("registering a credential with a certificate NOT chaining to the trusted root") {
            Then("the server should reject the attestation") {
                shouldThrow<CertificateException> { env.scenario.register() }
            }
        }
    }

    Given("server configured with NoneAttestationStatementVerifier") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = NoneAttestationStatementProvider()
                    aaguid = AAGUID.ZERO
                }
            }
            relyingParty {
                attestation = AttestationConveyancePreference.DIRECT
                webAuthnManager = WebAuthnManager(
                    listOf(NoneAttestationStatementVerifier()),
                    NullCertPathTrustworthinessVerifier(),
                    DefaultSelfAttestationTrustworthinessVerifier()
                )
            }
        }

        When("registering with None attestation") {
            Then("the server should accept the attestation") {
                env.scenario.register()
            }

            Then("authentication should succeed") {
                shouldNotThrowAny { env.scenario.authenticate() }
            }
        }
    }

    Given("server configured with NoneAttestationStatementVerifier but authenticator sends Packed") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = PackedBasicAttestationStatementProvider.createWithDemoAttestationKey()
                }
            }
            relyingParty {
                attestation = AttestationConveyancePreference.DIRECT
                webAuthnManager = WebAuthnManager(
                    listOf(NoneAttestationStatementVerifier()),
                    NullCertPathTrustworthinessVerifier(),
                    DefaultSelfAttestationTrustworthinessVerifier()
                )
            }
        }

        When("registering with mismatched attestation format") {
            Then("the server should reject the attestation") {
                shouldThrow<BadAttestationStatementException> { env.scenario.register() }
            }
        }
    }

    Given("server configured with PackedAttestationStatementVerifier but authenticator sends None") {
        val trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate()
        val env = WebAuthnTestEnvironment.create {
            clientPlatform {
                authenticator {
                    attestationStatementProvider = NoneAttestationStatementProvider()
                    aaguid = AAGUID.ZERO
                }
            }
            relyingParty {
                attestation = AttestationConveyancePreference.DIRECT
                webAuthnManager = WebAuthnManager(
                    listOf(PackedAttestationStatementVerifier()),
                    DefaultCertPathTrustworthinessVerifier(trustAnchorRepository),
                    DefaultSelfAttestationTrustworthinessVerifier()
                )
            }
        }

        When("registering with mismatched attestation format") {
            Then("the server should reject the attestation") {
                shouldThrow<BadAttestationStatementException> { env.scenario.register() }
            }
        }
    }
})
