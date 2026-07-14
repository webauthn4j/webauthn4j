package com.webauthn4j.test.integration.environment

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.ctap.client.PublicKeyCredentialCreationContext
import com.webauthn4j.ctap.client.PublicKeyCredentialRequestContext
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.Challenge
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import com.webauthn4j.server.ServerProperty

/**
 * Standard WebAuthn scenario that orchestrates the registration/authentication
 * protocol flow between a [RelyingParty] and a [ClientPlatform].
 *
 * Each flow is decomposed into step objects representing protocol states:
 * - Registration: [RegistrationOptionsCreated] → [RegistrationCredentialCreated] → [RegistrationResult]
 * - Authentication: [AuthenticationOptionsCreated] → [AuthenticationAssertionCreated] → [AuthenticationResult]
 */
class StandardScenario internal constructor(
    val relyingParty: RelyingParty,
    val defaultClientPlatform: ClientPlatform,
    private val objectConverter: ObjectConverter,
) {
    // ============================================================
    // Registration Flow
    // ============================================================

    fun createRegistrationOptions(
        pubKeyCredParams: List<PublicKeyCredentialParameters>? = null,
        excludeCredentials: List<PublicKeyCredentialDescriptor>? = null,
        authenticatorAttachment: AuthenticatorAttachment? = null,
    ): RegistrationOptionsCreated {
        val rp = relyingParty
        val challenge = DefaultChallenge()
        val options = PublicKeyCredentialCreationOptions(
            PublicKeyCredentialRpEntity(rp.rpId, rp.rpName),
            PublicKeyCredentialUserEntity(ByteArray(32), "user@example.com", "Test User"),
            challenge,
            pubKeyCredParams ?: listOf(
                PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
            ),
            null,
            excludeCredentials ?: emptyList(),
            AuthenticatorSelectionCriteria(
                authenticatorAttachment,
                rp.residentKeyRequirement == ResidentKeyRequirement.REQUIRED,
                rp.residentKeyRequirement,
                rp.userVerificationRequirement
            ),
            rp.attestation,
            null
        )
        return RegistrationOptionsCreated(options, challenge, this)
    }

    /** Convenience: full registration flow with all defaults. */
    suspend fun register(): RegistrationResult =
        createRegistrationOptions()
            .createCredential(defaultClientPlatform)
            .verifyOnServer()

    // ============================================================
    // Authentication Flow
    // ============================================================

    fun createAuthenticationOptions(
        allowCredentials: List<PublicKeyCredentialDescriptor>? = null,
        userVerificationRequirement: UserVerificationRequirement? = null,
    ): AuthenticationOptionsCreated {
        val rp = relyingParty
        val challenge = DefaultChallenge()
        val options = PublicKeyCredentialRequestOptions(
            challenge, null, rp.rpId, allowCredentials,
            userVerificationRequirement ?: rp.userVerificationRequirement, null
        )
        return AuthenticationOptionsCreated(options, challenge, this)
    }

    /** Convenience: full authentication flow with all defaults. */
    suspend fun authenticate(): AuthenticationResult =
        createAuthenticationOptions()
            .getAssertion()
            .verifyOnServer()

    // ============================================================
    // Step Objects — Registration
    // ============================================================

    /** RP has created registration options. Ready to send to client platform. */
    class RegistrationOptionsCreated internal constructor(
        val publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
        internal val challenge: Challenge,
        internal val scenario: StandardScenario,
    ) {
        /**
         * Send to client platform: calls WebAuthnClient.create().
         * @param overrideChallenge If set, replaces the challenge (simulates challenge fixation attack).
         * @param overrideOrigin If set, replaces the origin (simulates cross-origin attack).
         */
        suspend fun createCredential(
            clientPlatform: ClientPlatform = scenario.defaultClientPlatform,
            overrideChallenge: Challenge? = null,
            overrideOrigin: Origin? = null,
        ): RegistrationCredentialCreated {
            val effectiveOptions = if (overrideChallenge != null) {
                PublicKeyCredentialCreationOptions(
                    publicKeyCredentialCreationOptions.rp,
                    publicKeyCredentialCreationOptions.user,
                    overrideChallenge,
                    publicKeyCredentialCreationOptions.pubKeyCredParams,
                    publicKeyCredentialCreationOptions.timeout,
                    publicKeyCredentialCreationOptions.excludeCredentials,
                    publicKeyCredentialCreationOptions.authenticatorSelection,
                    publicKeyCredentialCreationOptions.attestation,
                    publicKeyCredentialCreationOptions.extensions
                )
            } else {
                publicKeyCredentialCreationOptions
            }
            val context = PublicKeyCredentialCreationContext(
                overrideOrigin ?: clientPlatform.origin,
                clientPINProvider = { clientPlatform.clientPINValue.toByteArray() }
            )
            val credential = clientPlatform.webAuthnClient.create(effectiveOptions, context)
            return RegistrationCredentialCreated(credential, challenge, scenario)
        }
    }

    /** Client platform has created a credential. Ready for server verification. */
    class RegistrationCredentialCreated internal constructor(
        val credential: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>,
        private val challenge: Challenge,
        private val scenario: StandardScenario,
    ) {
        /** Server verifies the registration response. */
        fun verifyOnServer(
            rpId: String? = null,
            pubKeyCredParams: List<PublicKeyCredentialParameters>? = null,
        ): RegistrationResult {
            val rp = scenario.relyingParty
            val registrationRequest = RegistrationRequest(
                credential.response!!.attestationObject,
                credential.response!!.clientDataJSON,
                scenario.objectConverter.jsonMapper.writeValueAsString(credential.clientExtensionResults),
                credential.response!!.transports.map { it.value }.toSet()
            )
            val serverProperty = ServerProperty.builder()
                .origin(rp.origin)
                .rpId(rpId ?: rp.rpId)
                .challenge(this.challenge)
                .build()
            val params = RegistrationParameters(
                serverProperty, pubKeyCredParams, rp.userVerificationRequired, rp.userPresenceRequired
            )
            val data = rp.webAuthnManager.verify(registrationRequest, params)
            val record = CredentialRecordImpl(
                data.attestationObject!!, data.collectedClientData, data.clientExtensions, data.transports
            )

            // Store credential in RP for later authentication lookup
            rp.storeCredential(credential.rawId, record)

            return RegistrationResult(credential, data, record)
        }
    }

    // ============================================================
    // Step Objects — Authentication
    // ============================================================

    /** RP has created authentication options. Ready to send to client platform. */
    class AuthenticationOptionsCreated internal constructor(
        val publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions,
        private val challenge: Challenge,
        private val scenario: StandardScenario,
    ) {
        /**
         * Send to client platform: calls WebAuthnClient.get().
         * @param overrideChallenge If set, replaces the challenge (simulates challenge fixation attack).
         * @param overrideOrigin If set, replaces the origin (simulates cross-origin attack).
         */
        suspend fun getAssertion(
            clientPlatform: ClientPlatform = scenario.defaultClientPlatform,
            overrideChallenge: Challenge? = null,
            overrideOrigin: Origin? = null,
        ): AuthenticationAssertionCreated {
            val effectiveOptions = if (overrideChallenge != null) {
                PublicKeyCredentialRequestOptions(
                    overrideChallenge,
                    publicKeyCredentialRequestOptions.timeout,
                    publicKeyCredentialRequestOptions.rpId,
                    publicKeyCredentialRequestOptions.allowCredentials,
                    publicKeyCredentialRequestOptions.userVerification,
                    publicKeyCredentialRequestOptions.extensions
                )
            } else {
                publicKeyCredentialRequestOptions
            }
            val context = PublicKeyCredentialRequestContext(
                overrideOrigin ?: clientPlatform.origin,
                publicKeyCredentialSelectionHandler = { it.first() },
                clientPINProvider = { clientPlatform.clientPINValue.toByteArray() }
            )
            val credential = clientPlatform.webAuthnClient.get(effectiveOptions, context)
            return AuthenticationAssertionCreated(credential, challenge, scenario)
        }
    }

    /** Client platform has produced an assertion. Ready for server verification. */
    class AuthenticationAssertionCreated internal constructor(
        val credential: PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>,
        private val challenge: Challenge,
        private val scenario: StandardScenario,
    ) {
        /** Server verifies the authentication response. */
        fun verifyOnServer(
            rpId: String? = null,
            userVerificationRequired: Boolean? = null,
            allowCredentials: List<ByteArray>? = null,
        ): AuthenticationResult {
            val rp = scenario.relyingParty
            val credentialRecord = rp.lookupCredential(credential.rawId)
                ?: error("No credential found for ID. Did you register first?")

            val request = AuthenticationRequest(
                credential.rawId, ByteArray(32),
                credential.response!!.authenticatorData,
                credential.response!!.clientDataJSON,
                scenario.objectConverter.jsonMapper.writeValueAsString(credential.clientExtensionResults),
                credential.response!!.signature
            )
            val serverProperty = ServerProperty.builder()
                .origin(rp.origin)
                .rpId(rpId ?: rp.rpId)
                .challenge(this.challenge)
                .build()
            val params = AuthenticationParameters(
                serverProperty, credentialRecord, allowCredentials,
                userVerificationRequired ?: rp.userVerificationRequired, rp.userPresenceRequired
            )
            val data = rp.webAuthnManager.verify(request, params)
            return AuthenticationResult(credential, data)
        }
    }

    // ============================================================
    // Result Classes
    // ============================================================

    data class RegistrationResult(
        val credential: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>,
        val registrationData: RegistrationData,
        val credentialRecord: CredentialRecord,
    )

    data class AuthenticationResult(
        val credential: PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>,
        val authenticationData: AuthenticationData,
    )
}
