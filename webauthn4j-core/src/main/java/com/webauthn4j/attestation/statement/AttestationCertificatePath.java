package com.webauthn4j.attestation.statement;

import com.webauthn4j.util.CertificateUtil;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class AttestationCertificatePath extends ArrayList<X509Certificate> {

    public AttestationCertificatePath(List<X509Certificate> certificates){
        this.addAll(certificates);
    }

    public AttestationCertificatePath(){
    }

    public CertPath createCertPath(){
        return CertificateUtil.generateCertPath(new ArrayList<>(this));
    }

    public AttestationCertificate getEndEntityAttestationCertificate(){
        if (this.isEmpty()) {
            throw new IllegalStateException();
        }
        return new AttestationCertificate(this.get(0));
    }
}
