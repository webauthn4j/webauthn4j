package com.webauthn4j.test.integration.environment

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.client.Origin

/**
 * Relying Party: configuration + server-side verification + credential store.
 * Does not contain any protocol flow logic (that's in [StandardScenario]).
 */
class RelyingParty internal constructor(
    val rpId: String,
    val rpName: String,
    val origin: Origin,
    val attestation: AttestationConveyancePreference,
    val residentKeyRequirement: ResidentKeyRequirement,
    val userVerificationRequirement: UserVerificationRequirement,
    val userVerificationRequired: Boolean,
    val userPresenceRequired: Boolean,
    val webAuthnManager: WebAuthnManager,
) {
    private val credentialStore = mutableMapOf<CredentialId, CredentialRecord>()

    fun storeCredential(credentialId: ByteArray, record: CredentialRecord) {
        credentialStore[CredentialId(credentialId)] = record
    }

    fun lookupCredential(credentialId: ByteArray): CredentialRecord? {
        return credentialStore[CredentialId(credentialId)]
    }

    fun deleteCredential(credentialId: ByteArray) {
        credentialStore.remove(CredentialId(credentialId))
    }

    private data class CredentialId(val bytes: ByteArray) {
        override fun equals(other: Any?) = other is CredentialId && bytes.contentEquals(other.bytes)
        override fun hashCode() = bytes.contentHashCode()
    }

    class Builder {
        var rpId: String = "example.com"
        var rpName: String = "WebAuthn4J Integration Test"
        var origin: Origin = Origin("https://example.com")
        var attestation: AttestationConveyancePreference = AttestationConveyancePreference.NONE
        var residentKeyRequirement: ResidentKeyRequirement = ResidentKeyRequirement.PREFERRED
        var userVerificationRequirement: UserVerificationRequirement = UserVerificationRequirement.PREFERRED
        var userVerificationRequired: Boolean = false
        var userPresenceRequired: Boolean = true
        var webAuthnManager: WebAuthnManager? = null

        internal fun build(): RelyingParty {
            val manager = webAuthnManager ?: WebAuthnManager.createNonStrictWebAuthnManager()
            return RelyingParty(
                rpId, rpName, origin, attestation,
                residentKeyRequirement, userVerificationRequirement,
                userVerificationRequired, userPresenceRequired, manager
            )
        }
    }
}
