package net.sharplab.springframework.security.webauthn.sample.domain.vo;

public class NoneAttestationStatementVO implements AttestationStatementVO {

    private static final String FORMAT = "none";

    @Override
    public String getFormat() {
        return FORMAT;
    }
}
