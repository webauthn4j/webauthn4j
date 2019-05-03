package com.webauthn4j.validator;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
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
public class AuthenticationObject<A extends ExtensionAuthenticatorOutput, C extends ExtensionClientOutput> {

    //~ Instance fields
    // ================================================================================================

    private final byte[] credentialId;
    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AuthenticatorData<A> authenticatorData;
    private final byte[] authenticatorDataBytes;
    private final AuthenticationExtensionsClientOutputs<C> clientExtensions;
    private final ServerProperty serverProperty;
    private final LocalDateTime timestamp;

    public AuthenticationObject(
            byte[] credentialId,
            CollectedClientData collectedClientData,
            byte[] collectedClientDataBytes,
            AuthenticatorData<A> authenticatorData,
            byte[] authenticatorDataBytes,
            AuthenticationExtensionsClientOutputs<C> clientExtensions,
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
            AuthenticatorData<A> authenticatorData,
            byte[] authenticatorDataBytes,
            AuthenticationExtensionsClientOutputs<C> clientExtensions,
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

    public AuthenticatorData<A> getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getAuthenticatorDataBytes() {
        return ArrayUtil.clone(authenticatorDataBytes);
    }

    public AuthenticationExtensionsClientOutputs<C> getClientExtensions() {
        return this.clientExtensions;
    }

    public ServerProperty getServerProperty() {
        return this.serverProperty;
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
                Objects.equals(timestamp, that.timestamp);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(collectedClientData, authenticatorData, clientExtensions, serverProperty, timestamp);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(collectedClientDataBytes);
        result = 31 * result + Arrays.hashCode(authenticatorDataBytes);
        return result;
    }
}
