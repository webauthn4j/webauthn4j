package com.webauthn4j.verifier;

import com.webauthn4j.authenticator.CoreAuthenticator;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Objects;

/**
 * Internal data transfer object for authentication data
 */
public class CoreAuthenticationObject {

    //~ Instance fields
    // ================================================================================================

    private final byte[] credentialId;
    private final AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData;
    private final byte[] authenticatorDataBytes;
    private final byte[] clientDataHash;
    private final CoreServerProperty serverProperty;

    private final CoreAuthenticator authenticator;

    @SuppressWarnings("squid:S00107")
    public CoreAuthenticationObject(
            @NotNull byte[] credentialId,
            @NotNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            @NotNull byte[] authenticatorDataBytes,
            @NotNull byte[] clientDataHash,
            @NotNull CoreServerProperty serverProperty,
            @NotNull CoreAuthenticator authenticator) {

        AssertUtil.notNull(credentialId, "credentialId must not be null");
        AssertUtil.notNull(authenticatorData, "authenticatorData must not be null");
        AssertUtil.notNull(authenticatorDataBytes, "authenticatorDataBytes must not be null");
        AssertUtil.notNull(clientDataHash, "clientDataHash must not be null");
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");
        AssertUtil.notNull(authenticator, "authenticator must not be null");

        this.credentialId = ArrayUtil.clone(credentialId);
        this.authenticatorData = authenticatorData;
        this.authenticatorDataBytes = ArrayUtil.clone(authenticatorDataBytes);
        this.clientDataHash = ArrayUtil.clone(clientDataHash);
        this.serverProperty = serverProperty;
        this.authenticator = authenticator;
    }

    public @NotNull byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public @NotNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> getAuthenticatorData() {
        return authenticatorData;
    }

    public @NotNull byte[] getAuthenticatorDataBytes() {
        return ArrayUtil.clone(authenticatorDataBytes);
    }

    public @NotNull byte[] getClientDataHash() {
        return ArrayUtil.clone(clientDataHash);
    }

    public @NotNull CoreServerProperty getServerProperty() {
        return this.serverProperty;
    }

    public @NotNull CoreAuthenticator getAuthenticator() {
        return authenticator;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreAuthenticationObject that = (CoreAuthenticationObject) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Objects.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(authenticatorDataBytes, that.authenticatorDataBytes) &&
                Arrays.equals(clientDataHash, that.clientDataHash) &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(authenticator, that.authenticator);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(authenticatorData, serverProperty, authenticator);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(authenticatorDataBytes);
        result = 31 * result + Arrays.hashCode(clientDataHash);
        return result;
    }
}
