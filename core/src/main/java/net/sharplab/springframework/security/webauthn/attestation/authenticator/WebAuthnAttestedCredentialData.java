package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import java.io.Serializable;
import java.util.Arrays;

public class WebAuthnAttestedCredentialData implements Serializable {

    //~ Instance fields ================================================================================================
    private byte[] aaGuid;
    private byte[] credentialId;
    private AbstractCredentialPublicKey credentialPublicKey;


    public byte[] getAaGuid() {
        return aaGuid;
    }

    public void setAaGuid(byte[] aaGuid) {
        this.aaGuid = aaGuid;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(byte[] credentialId) {
        this.credentialId = credentialId;
    }

    public AbstractCredentialPublicKey getCredentialPublicKey() {
        return credentialPublicKey;
    }

    public void setCredentialPublicKey(AbstractCredentialPublicKey credentialPublicKey) {
        this.credentialPublicKey = credentialPublicKey;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAttestedCredentialData)) return false;

        WebAuthnAttestedCredentialData that = (WebAuthnAttestedCredentialData) o;

        if (!Arrays.equals(aaGuid, that.aaGuid)) return false;
        if (!Arrays.equals(credentialId, that.credentialId)) return false;
        return credentialPublicKey != null ? credentialPublicKey.equals(that.credentialPublicKey) : that.credentialPublicKey == null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(aaGuid);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + (credentialPublicKey != null ? credentialPublicKey.hashCode() : 0);
        return result;
    }
}
