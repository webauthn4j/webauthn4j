package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType.PUBLIC_KEY
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier.*
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.NotAllowedAlgorithmException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import kotlin.reflect.KClass

@Tags("Parameter")
class AlgorithmSpec : BehaviorSpec({

    // ============================================================
    // Client-side: RP requested algorithms × Authenticator supported algorithms
    // ============================================================

    data class NegotiationCase(
        val rpRequests: List<com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier>,
        val authSupports: Set<com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier>,
        val success: Boolean,
        val expectedKeyType: KClass<out COSEKey>? = null,
    )

    listOf(
        //                RP requests      Auth supports    success  key type
        NegotiationCase(listOf(ES256),      setOf(ES256),    true,    EC2COSEKey::class),
        NegotiationCase(listOf(RS256),      setOf(RS256),    true,    RSACOSEKey::class),
        NegotiationCase(listOf(RS256,ES256),setOf(ES256),    true,    EC2COSEKey::class),
        NegotiationCase(listOf(ES256),      setOf(ES256,RS256), true, EC2COSEKey::class),
        NegotiationCase(listOf(ES256),      setOf(RS256),    false),
        NegotiationCase(listOf(RS256),      setOf(ES256),    false),
        NegotiationCase(listOf(RS512),      setOf(ES256),    false),
    ).forEach { case ->

        Given("RP requests ${case.rpRequests} × authenticator supports ${case.authSupports}") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator { algorithms = case.authSupports }
                }
                relyingParty()
            }
            val pubKeyCredParams = case.rpRequests.map { PublicKeyCredentialParameters(PUBLIC_KEY, it) }

            When("registering a credential") {
                if (case.success) {
                    Then("registration should succeed with ${case.expectedKeyType!!.simpleName}") {
                        val reg = env.scenario.createRegistrationOptions(pubKeyCredParams = pubKeyCredParams)
                            .createCredential().verifyOnServer()
                        val coseKey = reg.registrationData.attestationObject!!.authenticatorData
                            .attestedCredentialData.shouldNotBeNull().coseKey
                        coseKey!!::class shouldBe case.expectedKeyType
                    }
                } else {
                    Then("CTAP2_ERR_UNSUPPORTED_ALGORITHM should be thrown") {
                        val ex = shouldThrow<CtapErrorException> {
                            env.scenario.createRegistrationOptions(pubKeyCredParams = pubKeyCredParams)
                                .createCredential().verifyOnServer()
                        }
                        ex.message.shouldContain("CTAP2_ERR_UNSUPPORTED_ALGORITHM")
                    }
                }
            }
        }
    }

    // ============================================================
    // Server-side: pubKeyCredParams verification
    // ============================================================

    data class ServerVerificationCase(
        val authenticatorAlgorithm: com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier,
        val serverPubKeyCredParams: List<com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier>?,
        val success: Boolean,
    )

    listOf(
        //                          authenticator algorithm  server pubKeyCredParams   success
        // null = accept any
        ServerVerificationCase(     ES256,          null,                     true),
        ServerVerificationCase(     RS256,          null,                     true),
        // exact match
        ServerVerificationCase(     ES256,          listOf(ES256),            true),
        ServerVerificationCase(     RS256,          listOf(RS256),            true),
        // multiple allowed, one matches
        ServerVerificationCase(     ES256,          listOf(RS256, ES256),     true),
        // mismatch
        ServerVerificationCase(     ES256,          listOf(RS256),            false),
        ServerVerificationCase(     RS256,          listOf(ES256),            false),
        ServerVerificationCase(     ES256,          listOf(RS512),            false),
    ).forEach { case ->

        Given("server verification: authenticator=${case.authenticatorAlgorithm}, pubKeyCredParams=${case.serverPubKeyCredParams}") {
            val env = WebAuthnTestEnvironment.create {
                clientPlatform {
                    authenticator { algorithms = setOf(case.authenticatorAlgorithm) }
                }
                relyingParty()
            }
            val rpPubKeyCredParams = listOf(PublicKeyCredentialParameters(PUBLIC_KEY, case.authenticatorAlgorithm))
            val serverPubKeyCredParams = case.serverPubKeyCredParams?.map { PublicKeyCredentialParameters(PUBLIC_KEY, it) }

            When("registering and verifying on server") {
                if (case.success) {
                    Then("the server should accept the credential") {
                        env.scenario.createRegistrationOptions(pubKeyCredParams = rpPubKeyCredParams)
                            .createCredential()
                            .verifyOnServer(pubKeyCredParams = serverPubKeyCredParams)
                    }
                } else {
                    Then("NotAllowedAlgorithmException should be thrown") {
                        shouldThrow<NotAllowedAlgorithmException> {
                            env.scenario.createRegistrationOptions(pubKeyCredParams = rpPubKeyCredParams)
                                .createCredential()
                                .verifyOnServer(pubKeyCredParams = serverPubKeyCredParams)
                        }
                    }
                }
            }
        }
    }
})
