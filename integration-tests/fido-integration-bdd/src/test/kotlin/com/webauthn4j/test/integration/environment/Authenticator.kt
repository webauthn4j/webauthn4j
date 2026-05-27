package com.webauthn4j.test.integration.environment

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.GetAssertionConsentRequest
import com.webauthn4j.ctap.authenticator.MakeCredentialConsentRequest
import com.webauthn4j.ctap.authenticator.UserVerificationHandler
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FBasicAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.PackedBasicAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.authenticator.data.settings.*
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.transport.internal.InternalTransport
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import java.util.*

/** Runtime representation of a built authenticator. */
data class Authenticator(
    val transport: InternalTransport,
    val propertyStore: AuthenticatorPropertyStore,
) {
    class Builder {
        var attestationStatementProvider: AttestationStatementProvider =
            PackedBasicAttestationStatementProvider.createWithDemoAttestationKey()
        var fidoU2FAttestationStatementProvider: FIDOU2FBasicAttestationStatementProvider =
            FIDOU2FBasicAttestationStatementProvider.createWithDemoAttestationKey()
        var aaguid: AAGUID = AAGUID(UUID.randomUUID())
        var algorithms: Set<COSEAlgorithmIdentifier> = setOf(COSEAlgorithmIdentifier.ES256)
        var residentKey: ResidentKeySetting = ResidentKeySetting.IF_REQUIRED
        var clientPIN: ClientPINSetting = ClientPINSetting.ENABLED
        var userVerification: UserVerificationSetting = UserVerificationSetting.READY
        var userPresence: UserPresenceSetting = UserPresenceSetting.SUPPORTED
        var attachment: AttachmentSetting = AttachmentSetting.CROSS_PLATFORM
        var credentialSelector: CredentialSelectorSetting = CredentialSelectorSetting.CLIENT_PLATFORM
        var resetProtection: ResetProtectionSetting = ResetProtectionSetting.DISABLED
        var transports: Set<AuthenticatorTransport> = setOf(AuthenticatorTransport.USB)
        var propertyStore: AuthenticatorPropertyStore? = null

        internal fun build(objectConverter: ObjectConverter): Authenticator {
            val effectivePropertyStore = (propertyStore ?: InMemoryAuthenticatorPropertyStore()).apply {
                algorithms = this@Builder.algorithms
            }
            val ctapAuthenticator = createCtapAuthenticator(objectConverter, effectivePropertyStore)
            val uvHandler = createUserVerificationHandler()
            val transport = InternalTransport(ctapAuthenticator, uvHandler)
            return Authenticator(transport, effectivePropertyStore)
        }

        private fun createCtapAuthenticator(
            objectConverter: ObjectConverter,
            propertyStore: AuthenticatorPropertyStore,
        ): CtapAuthenticator {
            val credSelectionHandler = object : CredentialSelectionHandler {
                override suspend fun onSelect(list: List<Credential>): Credential = list.first()
            }
            return CtapAuthenticator(
                objectConverter, attestationStatementProvider, fidoU2FAttestationStatementProvider,
                transports, emptyList(), propertyStore, credentialSelectionHandler = credSelectionHandler
            ).apply {
                aaguid = this@Builder.aaguid
                platform = attachment
                residentKey = this@Builder.residentKey
                clientPIN = this@Builder.clientPIN
                resetProtection = this@Builder.resetProtection
                userPresence = this@Builder.userPresence
                userVerification = this@Builder.userVerification
                credentialSelector = this@Builder.credentialSelector
            }
        }

        private fun createUserVerificationHandler(): UserVerificationHandler {
            val uvSetting = userVerification
            return object : UserVerificationHandler {
                override fun getUserVerificationOption(rpId: String?): UserVerificationOption? = when (uvSetting) {
                    UserVerificationSetting.READY -> UserVerificationOption(true)
                    UserVerificationSetting.NOT_READY -> UserVerificationOption(false)
                    UserVerificationSetting.NOT_SUPPORTED -> null
                }
                override suspend fun onMakeCredentialConsentRequested(r: MakeCredentialConsentRequest) = true
                override suspend fun onGetAssertionConsentRequested(r: GetAssertionConsentRequest) = true
            }
        }
    }
}
