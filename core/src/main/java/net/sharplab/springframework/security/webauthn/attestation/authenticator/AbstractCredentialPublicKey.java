package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.security.Signature;


public abstract class AbstractCredentialPublicKey implements CredentialPublicKey {

    @JsonProperty("1")
    private int keyType;
    @JsonProperty("2")
    private byte[] keyId;
    @JsonProperty("3")
    private int algorithm;
    @JsonProperty("4")
    private int[] keyOpts;
    @JsonProperty("5")
    private byte[] baseIV;

    public int getKeyType() {
        return keyType;
    }

    public void setKeyType(int keyType) {
        this.keyType = keyType;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public void setKeyId(byte[] keyId) {
        this.keyId = keyId;
    }

    public int getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(int algorithm) {
        this.algorithm = algorithm;
    }

    public int[] getKeyOpts() {
        return keyOpts;
    }

    public void setKeyOpts(int[] keyOpts) {
        this.keyOpts = keyOpts;
    }

    public byte[] getBaseIV() {
        return baseIV;
    }

    public void setBaseIV(byte[] baseIV) {
        this.baseIV = baseIV;
    }

    @Override
    public boolean verifySignature(byte[] signature, byte[] data) {
        try {
            //公開鍵に基づくverifier
            Signature verifier = Signature.getInstance(getAlgorithmName());
            verifier.initVerify(getPublicKey());
            //検証
            verifier.update(data);

            return verifier.verify(signature);
        } catch (@SuppressWarnings("squid:S1166") Exception e) {
            return false;
        }
    }

    protected abstract String getAlgorithmName();
}
