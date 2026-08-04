package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.BadSignatureException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class AttestationSignatureSpec : BehaviorSpec({

    Given("a test environment with attestation verification") {
        val env = WebAuthnTestEnvironment.forTestsWithAttestationVerification()

        When("registering with a tampered attestation signature") {
            val credentialCreated = env.scenario.server.createRegistrationOptions()
                .clientPlatform.createCredential()

            Then("BadSignatureException should be thrown") {
                shouldThrow<BadSignatureException> {
                    credentialCreated.server.verify(
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
})
