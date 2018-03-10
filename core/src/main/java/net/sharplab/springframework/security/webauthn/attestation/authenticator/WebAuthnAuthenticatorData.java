package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.extension.Extension;
import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

public class WebAuthnAuthenticatorData implements Serializable {
    public static final byte BIT_UP = (byte) 0b00000001;
    public static final byte BIT_UV = (byte) 0b00000100;
    public static final byte BIT_AT = (byte) 0b01000000;
    public static final byte BIT_ED = (byte) 0b10000000;

    private byte[] rpIdHash;
    private byte flags;
    private long counter;
    private WebAuthnAttestedCredentialData attestationData;
    private List<Extension> extensions;

    public WebAuthnAuthenticatorData(){}

    public byte[] getRpIdHash() {
        return rpIdHash;
    }

    public void setRpIdHash(byte[] rpIdHash) {
        this.rpIdHash = rpIdHash;
    }

    public byte getFlags() {
        return flags;
    }

    public void setFlags(byte flags) {
        this.flags = flags;
    }

    public boolean isFlagUP() {
        return (this.flags & BIT_UP) != 0;
    }

    public void setFlagUP(boolean flagUP) {
        if (flagUP) {
            this.flags |= BIT_UP;
        }
        else {
            this.flags &= ~BIT_UP;
        }
    }

    public boolean isFlagUV() {
        return (this.flags & BIT_UV) != 0;
    }

    public void setFlagUV(boolean flagUV) {
        if (flagUV) {
            this.flags |= BIT_UV;
        }
        else {
            this.flags &= ~BIT_UV;
        }
    }

    public boolean isFlagAT() {
        return (this.flags & BIT_AT) != 0;
    }

    public void setFlagAT(boolean flagAT) {
        if (flagAT) {
            this.flags |= BIT_AT;
        }
        else {
            this.flags &= ~BIT_AT;
        }
    }

    public boolean isFlagED() {
        return (this.flags & BIT_ED) != 0;
    }

    public void setFlagED(boolean flagED) {
        if (flagED) {
            this.flags |= BIT_ED;
        }
        else {
            this.flags &= ~BIT_ED;
        }
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

    public WebAuthnAttestedCredentialData getAttestationData() {
        return attestationData;
    }

    public void setAttestationData(WebAuthnAttestedCredentialData attestationData) {
        this.attestationData = attestationData;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<Extension> extensions) {
        this.extensions = extensions;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAuthenticatorData)) return false;

        WebAuthnAuthenticatorData that = (WebAuthnAuthenticatorData) o;

        if (flags != that.flags) return false;
        if (counter != that.counter) return false;
        if (!Arrays.equals(rpIdHash, that.rpIdHash)) return false;
        if (attestationData != null ? !attestationData.equals(that.attestationData) : that.attestationData != null) return false;
        return extensions != null ? extensions.equals(that.extensions) : that.extensions == null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(rpIdHash);
        result = 31 * result + (int) flags;
        result = 31 * result + (int) (counter ^ (counter >>> 32));
        result = 31 * result + (attestationData != null ? attestationData.hashCode() : 0);
        result = 31 * result + (extensions != null ? extensions.hashCode() : 0);
        return result;
    }
}
