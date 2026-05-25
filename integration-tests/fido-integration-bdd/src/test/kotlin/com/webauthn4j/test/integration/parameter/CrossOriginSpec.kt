package com.webauthn4j.test.integration.parameter

import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec

/**
 * WebAuthn Spec 7.1 steps 10-11, 7.2 steps 13-14:
 * - If crossOrigin is true, RP must expect iframe context
 * - If topOrigin is present, verify it matches expected top-level origin
 *
 * All tests disabled (xGiven): the test DSL does not yet support crossOrigin/topOrigin overrides.
 */
@Tags("Parameter")
class CrossOriginSpec : BehaviorSpec({

    // TODO: Requires DSL support for crossOrigin/topOrigin on ClientPlatform and ServerProperty

    xGiven("a credential created in a cross-origin iframe") {
        When("the server verifies with matching topOrigin") {
            Then("registration should succeed") {
            }
        }

        When("the server verifies with mismatched topOrigin") {
            Then("registration should fail") {
            }
        }
    }

    xGiven("an assertion from a cross-origin iframe") {
        When("the server verifies with matching topOrigin") {
            Then("authentication should succeed") {
            }
        }

        When("the server verifies with mismatched topOrigin") {
            Then("authentication should fail") {
            }
        }
    }
})
