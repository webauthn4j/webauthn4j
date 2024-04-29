package com.webauthn4j.validator;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

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
            @NotNull byte[] credentialId,
            @NotNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            @NotNull byte[] authenticatorDataBytes,
            @NotNull CollectedClientData collectedClientData,
            @NotNull byte[] collectedClientDataBytes,
            @Nullable AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions,
            @NotNull ServerProperty serverProperty,
            @NotNull Authenticator authenticator) {

        super(credentialId, authenticatorData, authenticatorDataBytes, MessageDigestUtil.createSHA256().digest(collectedClientDataBytes), serverProperty, authenticator);

        AssertUtil.notNull(collectedClientData, "collectedClientData must not be null");
        AssertUtil.notNull(collectedClientDataBytes, "collectedClientDataBytes must not be null");

        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = ArrayUtil.clone(collectedClientDataBytes);
        this.clientExtensions = clientExtensions;
    }

    public @NotNull CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public @NotNull byte[] getCollectedClientDataBytes() {
        return ArrayUtil.clone(collectedClientDataBytes);
    }

    public @Nullable AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> getClientExtensions() {
        return this.clientExtensions;
    }

    @Override
    public @NotNull ServerProperty getServerProperty() {
        return (ServerProperty) super.getServerProperty();
    }

    @Override
    public @NotNull Authenticator getAuthenticator() {
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
