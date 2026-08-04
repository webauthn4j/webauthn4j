package com.webauthn4j.test.integration.environment

import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.CollectedClientDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.ctap.client.PublicKeyCredentialCreationContext
import com.webauthn4j.ctap.client.PublicKeyCredentialRequestContext
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.CollectedClientData
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.Challenge
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import com.webauthn4j.server.ServerProperty

/**
 * Standard WebAuthn scenario that orchestrates the registration/authentication
 * protocol flow between a [RelyingParty] and a [ClientPlatform].
 *
 * Each flow is decomposed into step objects representing protocol states,
 * with actor-scoped accessors ([server] / [clientPlatform][RegistrationOptionsCreated.clientPlatform])
 * that make it clear which entity performs each step:
 *
 * ```
 * scenario.server.createRegistrationOptions()
 *     .clientPlatform.createCredential()
 *     .server.verify()
 * ```
 */
class StandardScenario internal constructor(
    val relyingParty: RelyingParty,
    val defaultClientPlatform: ClientPlatform,
    private val objectConverter: ObjectConverter,
) {
    val server = ServerActions()

    /** Convenience: full registration flow with all defaults. */
    suspend fun register(): RegistrationResult =
        server.createRegistrationOptions()
            .clientPlatform.createCredential()
            .server.verify()

    /** Convenience: full authentication flow with all defaults. */
    suspend fun authenticate(): AuthenticationResult =
        server.createAuthenticationOptions()
            .clientPlatform.getAssertion()
            .server.verify()

    // ============================================================
    // Server Actions (top-level)
    // ============================================================

    inner class ServerActions {
        fun createRegistrationOptions(
            pubKeyCredParams: List<PublicKeyCredentialParameters>? = null,
            excludeCredentials: List<PublicKeyCredentialDescriptor>? = null,
            authenticatorAttachment: AuthenticatorAttachment? = null,
            residentKeyRequirement: ResidentKeyRequirement? = null,
            userVerificationRequirement: UserVerificationRequirement? = null,
            attestation: AttestationConveyancePreference? = null,
            extensions: AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>? = null,
            timeout: Long? = null,
            hints: List<PublicKeyCredentialHints>? = null,
            attestationFormats: List<String>? = null,
        ): RegistrationOptionsCreated {
            val rp = relyingParty
            val challenge = DefaultChallenge()
            val effectiveResidentKeyRequirement = residentKeyRequirement ?: rp.residentKeyRequirement
            val options = PublicKeyCredentialCreationOptions(
                PublicKeyCredentialRpEntity(rp.rpId, rp.rpName),
                PublicKeyCredentialUserEntity(ByteArray(32), "user@example.com", "Test User"),
                challenge,
                pubKeyCredParams ?: listOf(
                    PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
                ),
                timeout,
                excludeCredentials ?: emptyList(),
                AuthenticatorSelectionCriteria(
                    authenticatorAttachment,
                    effectiveResidentKeyRequirement == ResidentKeyRequirement.REQUIRED,
                    effectiveResidentKeyRequirement,
                    userVerificationRequirement ?: rp.userVerificationRequirement
                ),
                hints,
                attestation ?: rp.attestation,
                attestationFormats,
                extensions
            )
            return RegistrationOptionsCreated(options, challenge, this@StandardScenario)
        }

        fun createAuthenticationOptions(
            allowCredentials: List<PublicKeyCredentialDescriptor>? = null,
            userVerificationRequirement: UserVerificationRequirement? = null,
            extensions: AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>? = null,
            timeout: Long? = null,
            hints: List<PublicKeyCredentialHints>? = null,
        ): AuthenticationOptionsCreated {
            val rp = relyingParty
            val challenge = DefaultChallenge()
            val options = PublicKeyCredentialRequestOptions(
                challenge, timeout, rp.rpId, allowCredentials,
                userVerificationRequirement ?: rp.userVerificationRequirement, hints, extensions
            )
            return AuthenticationOptionsCreated(options, challenge, this@StandardScenario)
        }
    }

    // ============================================================
    // Step Objects — Registration
    // ============================================================

    /** RP has created registration options. Ready to send to client platform. */
    class RegistrationOptionsCreated internal constructor(
        val publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
        internal val challenge: Challenge,
        internal val scenario: StandardScenario,
    ) {
        val clientPlatform = ClientPlatformActions()

        inner class ClientPlatformActions {
            /**
             * Send to client platform: calls WebAuthnClient.create().
             * @param challenge If set, replaces the challenge (simulates challenge fixation attack).
             * @param origin If set, replaces the origin (simulates cross-origin attack).
             */
            suspend fun createCredential(
                clientPlatform: ClientPlatform = scenario.defaultClientPlatform,
                challenge: Challenge? = null,
                origin: Origin? = null,
            ): RegistrationCredentialCreated {
                val effectiveOptions = if (challenge != null) {
                    PublicKeyCredentialCreationOptions(
                        publicKeyCredentialCreationOptions.rp,
                        publicKeyCredentialCreationOptions.user,
                        challenge,
                        publicKeyCredentialCreationOptions.pubKeyCredParams,
                        publicKeyCredentialCreationOptions.timeout,
                        publicKeyCredentialCreationOptions.excludeCredentials,
                        publicKeyCredentialCreationOptions.authenticatorSelection,
                        publicKeyCredentialCreationOptions.hints,
                        publicKeyCredentialCreationOptions.attestation,
                        publicKeyCredentialCreationOptions.attestationFormats,
                        publicKeyCredentialCreationOptions.extensions
                    )
                } else {
                    publicKeyCredentialCreationOptions
                }
                val context = PublicKeyCredentialCreationContext(
                    origin ?: clientPlatform.origin,
                    clientPINProvider = { clientPlatform.clientPINValue.toByteArray() }
                )
                val credential = clientPlatform.webAuthnClient.create(effectiveOptions, context)
                return RegistrationCredentialCreated(credential, this@RegistrationOptionsCreated.challenge, scenario)
            }
        }
    }

    /** Client platform has created a credential. Ready for server verification. */
    class RegistrationCredentialCreated internal constructor(
        val credential: PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput>,
        private val challenge: Challenge,
        private val scenario: StandardScenario,
    ) {
        val server = ServerActions()

        inner class ServerActions {
            /** Server verifies the registration response. */
            fun verify(
                rpId: String? = null,
                pubKeyCredParams: List<PublicKeyCredentialParameters>? = null,
                userVerificationRequired: Boolean? = null,
                userPresenceRequired: Boolean? = null,
                attestationObject: ByteArray? = null,
                clientData: ((CollectedClientData) -> CollectedClientData)? = null,
            ): RegistrationResult {
                val rp = scenario.relyingParty
                val originalClientDataJSON = credential.response!!.clientDataJSON
                val effectiveClientDataJSON = if (clientData != null) {
                    val converter = CollectedClientDataConverter(scenario.objectConverter)
                    val original = converter.convert(originalClientDataJSON)!!
                    converter.convertToBytes(clientData(original))
                } else {
                    originalClientDataJSON
                }
                val registrationRequest = RegistrationRequest(
                    attestationObject ?: credential.response!!.attestationObject,
                    effectiveClientDataJSON,
                    scenario.objectConverter.jsonMapper.writeValueAsString(credential.clientExtensionResults),
                    credential.response!!.transports.map { it.value }.toSet()
                )
                val serverProperty = ServerProperty.builder()
                    .origin(rp.origin)
                    .rpId(rpId ?: rp.rpId)
                    .challenge(challenge)
                    .build()
                val params = RegistrationParameters(
                    serverProperty, pubKeyCredParams,
                    userVerificationRequired ?: rp.userVerificationRequired,
                    userPresenceRequired ?: rp.userPresenceRequired
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
        val clientPlatform = ClientPlatformActions()

        inner class ClientPlatformActions {
            /**
             * Send to client platform: calls WebAuthnClient.get().
             * @param challenge If set, replaces the challenge (simulates challenge fixation attack).
             * @param origin If set, replaces the origin (simulates cross-origin attack).
             */
            suspend fun getAssertion(
                clientPlatform: ClientPlatform = scenario.defaultClientPlatform,
                challenge: Challenge? = null,
                origin: Origin? = null,
            ): AuthenticationAssertionCreated {
                val effectiveOptions = if (challenge != null) {
                    PublicKeyCredentialRequestOptions(
                        challenge,
                        publicKeyCredentialRequestOptions.timeout,
                        publicKeyCredentialRequestOptions.rpId,
                        publicKeyCredentialRequestOptions.allowCredentials,
                        publicKeyCredentialRequestOptions.userVerification,
                        publicKeyCredentialRequestOptions.hints,
                        publicKeyCredentialRequestOptions.extensions
                    )
                } else {
                    publicKeyCredentialRequestOptions
                }
                val context = PublicKeyCredentialRequestContext(
                    origin ?: clientPlatform.origin,
                    publicKeyCredentialSelectionHandler = { it.first() },
                    clientPINProvider = { clientPlatform.clientPINValue.toByteArray() }
                )
                val credential = clientPlatform.webAuthnClient.get(effectiveOptions, context)
                return AuthenticationAssertionCreated(credential, this@AuthenticationOptionsCreated.challenge, scenario)
            }
        }
    }

    /** Client platform has produced an assertion. Ready for server verification. */
    class AuthenticationAssertionCreated internal constructor(
        val credential: PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>,
        private val challenge: Challenge,
        private val scenario: StandardScenario,
    ) {
        val server = ServerActions()

        inner class ServerActions {
            /** Server verifies the authentication response. */
            fun verify(
                rpId: String? = null,
                userVerificationRequired: Boolean? = null,
                allowCredentials: List<ByteArray>? = null,
                userPresenceRequired: Boolean? = null,
                signature: ByteArray? = null,
                authenticatorData: ((AuthenticatorData<AuthenticationExtensionAuthenticatorOutput>) -> AuthenticatorData<AuthenticationExtensionAuthenticatorOutput>)? = null,
                clientData: ((CollectedClientData) -> CollectedClientData)? = null,
            ): AuthenticationResult {
                val rp = scenario.relyingParty
                val credentialRecord = rp.lookupCredential(credential.rawId)
                    ?: error("No credential found for ID. Did you register first?")

                val originalAuthenticatorData = credential.response!!.authenticatorData
                val effectiveAuthenticatorData = if (authenticatorData != null) {
                    val converter = AuthenticatorDataConverter(scenario.objectConverter)
                    val original = converter.convert<AuthenticationExtensionAuthenticatorOutput>(originalAuthenticatorData)
                    converter.convert(authenticatorData(original))
                } else {
                    originalAuthenticatorData
                }
                val originalClientDataJSON = credential.response!!.clientDataJSON
                val effectiveClientDataJSON = if (clientData != null) {
                    val converter = CollectedClientDataConverter(scenario.objectConverter)
                    val original = converter.convert(originalClientDataJSON)!!
                    converter.convertToBytes(clientData(original))
                } else {
                    originalClientDataJSON
                }
                val request = AuthenticationRequest(
                    credential.rawId, ByteArray(32),
                    effectiveAuthenticatorData,
                    effectiveClientDataJSON,
                    scenario.objectConverter.jsonMapper.writeValueAsString(credential.clientExtensionResults),
                    signature ?: credential.response!!.signature
                )
                val serverProperty = ServerProperty.builder()
                    .origin(rp.origin)
                    .rpId(rpId ?: rp.rpId)
                    .challenge(challenge)
                    .build()
                val params = AuthenticationParameters(
                    serverProperty, credentialRecord, allowCredentials,
                    userVerificationRequired ?: rp.userVerificationRequired,
                    userPresenceRequired ?: rp.userPresenceRequired
                )
                val data = rp.webAuthnManager.verify(request, params)
                return AuthenticationResult(credential, data)
            }
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
