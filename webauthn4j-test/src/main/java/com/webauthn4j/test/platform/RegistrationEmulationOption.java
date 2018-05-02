package com.webauthn4j.test.platform;

public class RegistrationEmulationOption {

    private boolean signatureOverrideEnabled = false;
    private byte[] signature = new byte[]{ 0x01, 0x23, 0x45, 0x67 };

    public boolean isSignatureOverrideEnabled() {
        return signatureOverrideEnabled;
    }

    public void setSignatureOverrideEnabled(boolean signatureOverrideEnabled) {
        this.signatureOverrideEnabled = signatureOverrideEnabled;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}
