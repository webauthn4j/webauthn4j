package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import java.util.List;

/**
 * FIDOU2FAttestationStatementVO
 */
public class FIDOU2FAttestationStatementVO implements AttestationStatementVO {

    private static final String FORMAT = "fido-u2f";

    private List<byte[]> x5c;
    private byte[] sig;

    public List<byte[]> getX5c() {
        return x5c;
    }

    public void setX5c(List<byte[]> x5c) {
        this.x5c = x5c;
    }

    public byte[] getSig() {
        return sig;
    }

    public void setSig(byte[] sig) {
        this.sig = sig;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }
}
