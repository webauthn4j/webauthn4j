package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import java.util.List;

/**
 * PackedAttestationStatementVO
 */
public class PackedAttestationStatementVO implements AttestationStatementVO {

    private static final String FORMAT = "packed";

    private String alg;
    private byte[] sig;
    private List<byte[]> x5c;
    private byte[] ecdaaKeyId;

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public byte[] getSig() {
        return sig;
    }

    public void setSig(byte[] sig) {
        this.sig = sig;
    }

    public List<byte[]> getX5c() {
        return x5c;
    }

    public void setX5c(List<byte[]> x5c) {
        this.x5c = x5c;
    }

    public byte[] getEcdaaKeyId() {
        return ecdaaKeyId;
    }

    public void setEcdaaKeyId(byte[] ecdaaKeyId) {
        this.ecdaaKeyId = ecdaaKeyId;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }
}
