package com.webauthn4j.test.integration.scenario

import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

@Tags("Scenario")
class CrossPlatformAuthenticationSpec : BehaviorSpec({

    Given("two client platforms sharing the same authenticator") {
        val sharedStore = InMemoryAuthenticatorPropertyStore()
        val env = WebAuthnTestEnvironment.create {
            clientPlatform { authenticator { propertyStore = sharedStore } }
            clientPlatform { authenticator { propertyStore = sharedStore } }
            relyingParty()
        }

        When("a credential is registered via the first client platform and authenticated via the second") {
            env.scenario.register()

            Then("the authentication should succeed") {
                shouldNotThrowAny {
                    env.scenario.relyingParty.createAuthenticationOptions()
                        .clientPlatform.getAssertion(clientPlatform = env.clientPlatforms[1])
                        .relyingParty.verify()
                }
            }
        }
    }
})
