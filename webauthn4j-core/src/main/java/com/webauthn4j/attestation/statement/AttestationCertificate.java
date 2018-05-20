package com.webauthn4j.attestation.statement;

import com.webauthn4j.validator.exception.CertificateException;

import java.security.cert.X509Certificate;
import java.util.Objects;

public class AttestationCertificate {

    private X509Certificate certificate;

    public AttestationCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getSubjectC(){
        return certificate.getSubjectX500Principal().getName("C");
    }

    public String getSubjectO(){
        return certificate.getSubjectX500Principal().getName("O");
    }

    public String getSubjectOU(){
        return certificate.getSubjectX500Principal().getName("OU");
    }

    public String getSubjectCN(){
        return certificate.getSubjectX500Principal().getName("CN");
    }

    public void validate(){
        if(getSubjectC().isEmpty()){
            throw new CertificateException("Subject-C must be present");
        }
        if(getSubjectO().isEmpty()){
            throw new CertificateException("Subject-O must be present");
        }
        if(!getSubjectOU().equals("Authenticator Attestation")){
            throw new CertificateException("Subject-OU must be present");
        }
        if(getSubjectCN().isEmpty()){
            throw new CertificateException("Subject-CN must be present");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttestationCertificate that = (AttestationCertificate) o;
        return Objects.equals(certificate, that.certificate);
    }

    @Override
    public int hashCode() {

        return Objects.hash(certificate);
    }
}
