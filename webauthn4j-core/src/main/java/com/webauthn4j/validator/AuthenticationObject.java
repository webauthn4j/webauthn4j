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

import java.util.Arrays;
import java.util.Objects;

/**
 * Internal data transfer object for authentication data
 */
@SuppressWarnings("Duplicates")
public class AuthenticationObject extends CoreAuthenticationObject{

    //~ Instance fields
    // ================================================================================================

    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions;

    @SuppressWarnings("squid:S00107")
    public AuthenticationObject(
            byte[] credentialId,
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            byte[] authenticatorDataBytes,
            CollectedClientData collectedClientData,
            byte[] collectedClientDataBytes,
            AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions,
            ServerProperty serverProperty,
            Authenticator authenticator) {

        super(credentialId, authenticatorData, authenticatorDataBytes, MessageDigestUtil.createSHA256().digest(collectedClientDataBytes), serverProperty, authenticator);

        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = ArrayUtil.clone(collectedClientDataBytes);
        this.clientExtensions = clientExtensions;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getCollectedClientDataBytes() {
        return ArrayUtil.clone(collectedClientDataBytes);
    }

    public AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> getClientExtensions() {
        return this.clientExtensions;
    }

    @Override
    public ServerProperty getServerProperty() {
        return (ServerProperty) super.getServerProperty();
    }

    @Override
    public Authenticator getAuthenticator() {
        return (Authenticator) super.getAuthenticator();
    }

    @Override
    public boolean equals(Object o) {
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
