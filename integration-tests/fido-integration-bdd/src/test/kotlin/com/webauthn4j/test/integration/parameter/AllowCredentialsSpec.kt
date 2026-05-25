package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.NotAllowedCredentialIdException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class AllowCredentialsSpec : BehaviorSpec({

    Given("server verification with allowCredentials=null (accept any credential)") {
        val env = WebAuthnTestEnvironment.createDefault()
        env.scenario.register()

        When("authenticating") {
            Then("the server should accept any credential") {
                env.scenario.createAuthenticationOptions()
                    .getAssertion()
                    .verifyOnServer(allowCredentials = null)
            }
        }
    }

    Given("server verification with allowCredentials containing multiple credential IDs") {
        val env = WebAuthnTestEnvironment.createDefault()
        val reg1 = env.scenario.register()

        When("authenticating with both IDs in server allowCredentials") {
            Then("the server should accept when credential is in the list") {
                val clientAllow = listOf(
                    PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, reg1.credential.rawId, null)
                )
                env.scenario.createAuthenticationOptions(allowCredentials = clientAllow)
                    .getAssertion()
                    .verifyOnServer(
                        allowCredentials = listOf(reg1.credential.rawId, ByteArray(32))
                    )
            }
        }
    }

    Given("server verification with empty allowCredentials list") {
        val env = WebAuthnTestEnvironment.createDefault()
        env.scenario.register()

        When("authenticating with empty list") {
            Then("NotAllowedCredentialIdException should be thrown") {
                shouldThrow<NotAllowedCredentialIdException> {
                    env.scenario.createAuthenticationOptions()
                        .getAssertion()
                        .verifyOnServer(allowCredentials = emptyList())
                }
            }
        }
    }
})
