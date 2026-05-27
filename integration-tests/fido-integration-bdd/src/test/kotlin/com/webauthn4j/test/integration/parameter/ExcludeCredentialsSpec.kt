package com.webauthn4j.test.integration.parameter

import com.webauthn4j.ctap.client.exception.CtapErrorException
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.string.shouldContain

@Tags("Parameter")
class ExcludeCredentialsSpec : BehaviorSpec({

    Given("an existing registered credential") {
        val env = WebAuthnTestEnvironment.createDefault()
        val firstRegistration = env.scenario.register()
        val existingCredentialId = firstRegistration.credential.rawId

        When("registering with the existing credential in excludeCredentials") {
            val excludeList = listOf(
                PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, existingCredentialId, null)
            )

            Then("CTAP2_ERR_CREDENTIAL_EXCLUDED should be thrown") {
                val ex = shouldThrow<CtapErrorException> {
                    env.scenario.createRegistrationOptions(excludeCredentials = excludeList)
                        .createCredential()
                        .verifyOnServer()
                }
                ex.message.shouldContain("CTAP2_ERR_CREDENTIAL_EXCLUDED")
            }
        }

        When("registering with a different credential in excludeCredentials") {
            val excludeList = listOf(
                PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, ByteArray(32), null)
            )

            Then("registration should succeed") {
                shouldNotThrowAny {
                    env.scenario.createRegistrationOptions(excludeCredentials = excludeList)
                        .createCredential()
                        .verifyOnServer()
                }
            }
        }
    }
})
