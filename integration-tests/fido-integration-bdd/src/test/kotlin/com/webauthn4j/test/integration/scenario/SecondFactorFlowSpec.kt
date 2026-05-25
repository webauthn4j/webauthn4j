package com.webauthn4j.test.integration.scenario

import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Scenario")
class SecondFactorFlowSpec : BehaviorSpec({

    Given("a relying party with resident key not required and UV preferred") {
        val env = WebAuthnTestEnvironment.create {
            clientPlatform { authenticator() }
            relyingParty {
                residentKeyRequirement = ResidentKeyRequirement.PREFERRED
                userVerificationRequirement = UserVerificationRequirement.PREFERRED
                userVerificationRequired = false
            }
        }

        When("a user registers and authenticates with credential ID in allowCredentials") {
            val registration = env.scenario.register()
            val allowCredentials = listOf(
                PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    registration.credential.rawId,
                    null
                )
            )
            Then("the authentication should succeed") {
                shouldNotThrowAny {
                    env.scenario.createAuthenticationOptions(
                        allowCredentials = allowCredentials,
                        userVerificationRequirement = UserVerificationRequirement.DISCOURAGED
                    )
                        .getAssertion()
                        .verifyOnServer(userVerificationRequired = false)
                }
            }
        }
    }
})
