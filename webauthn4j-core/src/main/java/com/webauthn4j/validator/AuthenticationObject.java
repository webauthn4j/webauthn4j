package com.webauthn4j.validator;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Objects;

/**
 * Internal data transfer object for authentication data
 */
@SuppressWarnings("Duplicates")
public class AuthenticationObject {

    //~ Instance fields
    // ================================================================================================

    private final byte[] credentialId;
    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData;
    private final byte[] authenticatorDataBytes;
    private final AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions;
    private final ServerProperty serverProperty;

    private final Authenticator authenticator;

    private final LocalDateTime timestamp;

    public AuthenticationObject(
            byte[] credentialId,
            CollectedClientData collectedClientData,
            byte[] collectedClientDataBytes,
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            byte[] authenticatorDataBytes,
            AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions,
            ServerProperty serverProperty,
            Authenticator authenticator
    ) {

        this(
                credentialId,
                collectedClientData,
                collectedClientDataBytes,
                authenticatorData,
                authenticatorDataBytes,
                clientExtensions,
                serverProperty,
                authenticator,
                LocalDateTime.now(Clock.systemUTC()));
    }

    @SuppressWarnings("squid:S00107")
    public AuthenticationObject(
            byte[] credentialId,
            CollectedClientData collectedClientData,
            byte[] collectedClientDataBytes,
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            byte[] authenticatorDataBytes,
            AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions,
            ServerProperty serverProperty,
            Authenticator authenticator,
            LocalDateTime timestamp) {
        this.credentialId = credentialId;
        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = collectedClientDataBytes;
        this.authenticatorData = authenticatorData;
        this.authenticatorDataBytes = authenticatorDataBytes;
        this.clientExtensions = clientExtensions;
        this.serverProperty = serverProperty;
        this.authenticator = authenticator;
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

    public AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> getClientExtensions() {
        return this.clientExtensions;
    }

    public ServerProperty getServerProperty() {
        return this.serverProperty;
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public LocalDateTime getTimestamp() {
        return this.timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationObject that = (AuthenticationObject) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Objects.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(collectedClientDataBytes, that.collectedClientDataBytes) &&
                Objects.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(authenticatorDataBytes, that.authenticatorDataBytes) &&
                Objects.equals(clientExtensions, that.clientExtensions) &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(authenticator, that.authenticator) &&
                Objects.equals(timestamp, that.timestamp);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(collectedClientData, authenticatorData, clientExtensions, serverProperty, authenticator, timestamp);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(collectedClientDataBytes);
        result = 31 * result + Arrays.hashCode(authenticatorDataBytes);
        return result;
    }
}
