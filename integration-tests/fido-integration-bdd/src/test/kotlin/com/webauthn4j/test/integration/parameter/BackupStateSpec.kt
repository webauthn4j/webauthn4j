package com.webauthn4j.test.integration.parameter

import com.webauthn4j.test.integration.environment.WebAuthnTestEnvironment
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.matchers.shouldBe

/**
 * WebAuthn Spec 7.1 steps 17-19, 7.2 steps 18-20:
 * - If BE=0 (single-device credential), BS must be 0
 * - If BE=1 (multi-device credential), BS can be 0 or 1
 * - BE must not change after registration
 */
@Tags("Parameter")
class BackupStateSpec : BehaviorSpec({

    // --- Single-device credential (BE=0) ---

    Given("a single-device credential (BE=0)") {
        val env = WebAuthnTestEnvironment.createDefault()
        val reg = env.scenario.register()

        When("checking flags after registration") {
            Then("BE should be 0") {
                reg.registrationData.attestationObject!!.authenticatorData.isFlagBE shouldBe false
            }

            Then("BS should be 0 (since BE=0, backup is not possible)") {
                reg.registrationData.attestationObject!!.authenticatorData.isFlagBS shouldBe false
            }
        }

        When("authenticating") {
            val auth = env.scenario.authenticate()

            Then("BE should remain 0 (must not change after registration)") {
                auth.authenticationData.authenticatorData!!.isFlagBE shouldBe false
            }

            Then("BS should be 0") {
                auth.authenticationData.authenticatorData!!.isFlagBS shouldBe false
            }
        }
    }

    // --- Multi-device credential (BE=1) ---
    // Currently ignored: webauthn4j-ctap authenticator does not support
    // BackupEligibility setting to generate multi-device credentials.

    xGiven("a multi-device credential (BE=1)") {
        // TODO: Requires authenticator support for generating backup-eligible credentials

        When("checking flags after registration") {
            Then("BE should be 1") {
            }

            Then("BS can be 0 or 1 depending on backup state") {
            }
        }

        When("authenticating") {
            Then("BE should remain 1 (must not change after registration)") {
            }
        }
    }
})
