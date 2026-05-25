package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.ints.shouldBeLessThanOrEqual

/**
 * WebAuthn Spec 7.1 steps 24-25:
 * - credentialId must be ≤ 1023 bytes
 * - credentialId must not be already registered for any user
 */
@Tags("Parameter")
class CredentialIdSpec : BehaviorSpec({

    Given("a registered credential") {
        val env = WebAuthnTestEnvironment.createDefault()
        val reg = env.scenario.register()

        When("checking the credential ID length") {
            Then("the credential ID should be ≤ 1023 bytes") {
                reg.credential.rawId.size shouldBeLessThanOrEqual 1023
            }
        }
    }

    Given("a credential already registered on the server") {
        val env = WebAuthnTestEnvironment.createDefault()
        val reg1 = env.scenario.register()

        When("attempting to authenticate with the registered credential") {
            val allowCredentials = listOf(
                PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, reg1.credential.rawId, null)
            )

            Then("the credential should be found in the server's store") {
                env.scenario.createAuthenticationOptions(allowCredentials = allowCredentials)
                    .getAssertion()
                    .verifyOnServer()
            }
        }
    }
})
