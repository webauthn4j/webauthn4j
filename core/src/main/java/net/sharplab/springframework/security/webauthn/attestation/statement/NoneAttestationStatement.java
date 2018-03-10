package net.sharplab.springframework.security.webauthn.attestation.statement;

import java.security.cert.X509Certificate;

public class NoneAttestationStatement implements WebAuthnAttestationStatement{

    public static final String FORMAT = "none";

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public boolean isSelfAttested() {
        return false; //TODO
    }

    @Override
    public X509Certificate getEndEntityCertificate() {
        return null; //TODO
    }
}
