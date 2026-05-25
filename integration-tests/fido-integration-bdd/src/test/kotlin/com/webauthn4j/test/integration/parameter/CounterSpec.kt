package com.webauthn4j.test.integration.parameter

import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import com.webauthn4j.verifier.exception.MaliciousCounterValueException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull

@Tags("Parameter")
class CounterSpec : BehaviorSpec({

    Given("a registered credential with counter enabled") {
        val env = WebAuthnTestEnvironment.createDefault()
        val registration = env.scenario.register()

        When("authenticating multiple times") {
            val allowCredentials = listOf(
                PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, registration.credential.rawId, null)
            )
            val auth1 = env.scenario.createAuthenticationOptions(allowCredentials = allowCredentials)
                .getAssertion()
                .verifyOnServer()
            val counter1 = auth1.authenticationData.authenticatorData.shouldNotBeNull().signCount

            val auth2 = env.scenario.createAuthenticationOptions(allowCredentials = allowCredentials)
                .getAssertion()
                .verifyOnServer()
            val counter2 = auth2.authenticationData.authenticatorData.shouldNotBeNull().signCount

            Then("the counter should increment with each authentication") {
                counter2 shouldBeGreaterThan counter1
            }
        }
    }

    // TODO: Clone detection is simulated by setting the server-side stored counter artificially high.
    //  A true authenticator clone test would require deep-copying ResidentUserCredential objects
    //  from the AuthenticatorPropertyStore, which is not supported by the current API.
    Given("clone detection with counter rollback") {
        val env = WebAuthnTestEnvironment.createDefault()

        When("the server's stored counter is higher than the authenticator's counter") {
            val registration = env.scenario.register()
            (registration.credentialRecord as CredentialRecordImpl).setCounter(999999)

            Then("MaliciousCounterValueException should be thrown") {
                shouldThrow<MaliciousCounterValueException> {
                    env.scenario.authenticate()
                }
            }
        }
    }
})
