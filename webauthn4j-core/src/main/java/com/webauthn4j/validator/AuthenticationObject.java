package com.webauthn4j.validator;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;

import java.time.Clock;
import java.time.LocalDateTime;

/**
 * Internal data transfer object for authentication data
 */
public class AuthenticationObject {

    //~ Instance fields
    // ================================================================================================

    private final byte[] credentialId;
    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData;
    private final byte[] authenticatorDataBytes;
    private final AuthenticationExtensionsClientOutputs<ExtensionClientOutput> clientExtensions;
    private final ServerProperty serverProperty;
    private final LocalDateTime timestamp;

    public AuthenticationObject(
            byte[] credentialId,
            CollectedClientData collectedClientData,
            byte[] collectedClientDataBytes,
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            byte[] authenticatorDataBytes,
            AuthenticationExtensionsClientOutputs<ExtensionClientOutput> clientExtensions,
            ServerProperty serverProperty
    ) {

        this(
                credentialId,
                collectedClientData,
                collectedClientDataBytes,
                authenticatorData,
                authenticatorDataBytes,
                clientExtensions,
                serverProperty,
                LocalDateTime.now(Clock.systemUTC()));
    }

    @SuppressWarnings("squid:S00107")
    public AuthenticationObject(
            byte[] credentialId,
            CollectedClientData collectedClientData,
            byte[] collectedClientDataBytes,
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            byte[] authenticatorDataBytes,
            AuthenticationExtensionsClientOutputs<ExtensionClientOutput> clientExtensions,
            ServerProperty serverProperty,
            LocalDateTime timestamp) {
        this.credentialId = credentialId;
        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = collectedClientDataBytes;
        this.authenticatorData = authenticatorData;
        this.authenticatorDataBytes = authenticatorDataBytes;
        this.clientExtensions = clientExtensions;
        this.serverProperty = serverProperty;
        this.timestamp = timestamp;
    }

    public byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getCollectedClientDataBytes() {
        return ArrayUtil.clone(collectedClientDataBytes);
    }

    public AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getAuthenticatorDataBytes() {
        return ArrayUtil.clone(authenticatorDataBytes);
    }

    public AuthenticationExtensionsClientOutputs<ExtensionClientOutput> getClientExtensions() {
        return clientExtensions;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}
