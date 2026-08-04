package com.webauthn4j.test.integration.parameter

import com.webauthn4j.data.client.ClientDataType
import com.webauthn4j.data.client.CollectedClientData
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.InconsistentClientDataTypeException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Parameter")
class ClientDataTypeSpec : BehaviorSpec({

    Given("a registered credential") {
        val env = WebAuthnTestEnvironment.createDefault()
        env.scenario.register()

        When("authenticating with clientData type 'webauthn.create' instead of 'webauthn.get'") {
            val assertionCreated = env.scenario.server.createAuthenticationOptions()
                .clientPlatform.getAssertion()

            Then("InconsistentClientDataTypeException should be thrown") {
                shouldThrow<InconsistentClientDataTypeException> {
                    assertionCreated.server.verify(
                        clientData = { it.withType(ClientDataType.WEBAUTHN_CREATE) }
                    )
                }
            }
        }
    }

    Given("a default test environment") {
        val env = WebAuthnTestEnvironment.createDefault()

        When("registering with clientData type 'webauthn.get' instead of 'webauthn.create'") {
            val credentialCreated = env.scenario.server.createRegistrationOptions()
                .clientPlatform.createCredential()

            Then("InconsistentClientDataTypeException should be thrown") {
                shouldThrow<InconsistentClientDataTypeException> {
                    credentialCreated.server.verify(
                        clientData = { it.withType(ClientDataType.WEBAUTHN_GET) }
                    )
                }
            }
        }
    }
})

private fun CollectedClientData.withType(type: ClientDataType): CollectedClientData =
    CollectedClientData(type, challenge, origin, crossOrigin, topOrigin, tokenBinding)
