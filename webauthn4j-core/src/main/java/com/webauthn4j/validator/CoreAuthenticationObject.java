package com.webauthn4j.validator;

import com.webauthn4j.authenticator.CoreAuthenticator;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.ArrayUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

/**
 * Internal data transfer object for authentication data
 */
@SuppressWarnings("Duplicates")
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
            @NonNull byte[] credentialId,
            @NonNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            @NonNull byte[] authenticatorDataBytes,
            @NonNull byte[] clientDataHash,
            @NonNull CoreServerProperty serverProperty,
            @NonNull CoreAuthenticator authenticator) {
        this.credentialId = ArrayUtil.clone(credentialId);
        this.authenticatorData = authenticatorData;
        this.authenticatorDataBytes = ArrayUtil.clone(authenticatorDataBytes);
        this.clientDataHash = ArrayUtil.clone(clientDataHash);
        this.serverProperty = serverProperty;
        this.authenticator = authenticator;
    }

    public @NonNull byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public @NonNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> getAuthenticatorData() {
        return authenticatorData;
    }

    public @NonNull byte[] getAuthenticatorDataBytes() {
        return ArrayUtil.clone(authenticatorDataBytes);
    }

    public @NonNull byte[] getClientDataHash() {
        return ArrayUtil.clone(clientDataHash);
    }

    public @NonNull CoreServerProperty getServerProperty() {
        return this.serverProperty;
    }

    public @NonNull CoreAuthenticator getAuthenticator() {
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
