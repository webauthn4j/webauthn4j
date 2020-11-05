package com.webauthn4j.validator;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

/**
 * Internal data transfer object for authentication data
 */
public class AuthenticationObject extends CoreAuthenticationObject {

    //~ Instance fields
    // ================================================================================================

    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions;

    @SuppressWarnings("squid:S00107")
    public AuthenticationObject(
            @NonNull byte[] credentialId,
            @NonNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            @NonNull byte[] authenticatorDataBytes,
            @NonNull CollectedClientData collectedClientData,
            @NonNull byte[] collectedClientDataBytes,
            @Nullable AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions,
            @NonNull ServerProperty serverProperty,
            @NonNull Authenticator authenticator) {

        super(credentialId, authenticatorData, authenticatorDataBytes, MessageDigestUtil.createSHA256().digest(collectedClientDataBytes), serverProperty, authenticator);

        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = ArrayUtil.clone(collectedClientDataBytes);
        this.clientExtensions = clientExtensions;
    }

    public @NonNull CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public @NonNull byte[] getCollectedClientDataBytes() {
        return ArrayUtil.clone(collectedClientDataBytes);
    }

    public @Nullable AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> getClientExtensions() {
        return this.clientExtensions;
    }

    @Override
    public @NonNull ServerProperty getServerProperty() {
        return (ServerProperty) super.getServerProperty();
    }

    @Override
    public @NonNull Authenticator getAuthenticator() {
        return (Authenticator) super.getAuthenticator();
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        AuthenticationObject that = (AuthenticationObject) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(collectedClientDataBytes, that.collectedClientDataBytes) &&
                Objects.equals(clientExtensions, that.clientExtensions);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), collectedClientData, clientExtensions);
        result = 31 * result + Arrays.hashCode(collectedClientDataBytes);
        return result;
    }
}
