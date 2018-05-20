package com.webauthn4j.attestation.statement;

import com.webauthn4j.validator.exception.CertificateException;
import sun.security.x509.X500Name;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


public class AttestationCertificate {

    public static final int CERTIFICATE_VERSION_3 = 3;
    public static final int NON_CA = -1;
    private static final Map<String, String> cHashMap;

    private X509Certificate certificate;

    static {
        cHashMap = new HashMap<>();
        cHashMap.put("", "");
    }

    public AttestationCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getSubjectCountry(){
        try {
            return getX500Name().getCountry();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String getSubjectOrganization(){
        try {
            return getX500Name().getOrganization();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String getSubjectOrganizationUnit(){
        try {
            return getX500Name().getOrganizationalUnit();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String getSubjectCommonName(){
        try {
            return getX500Name().getCommonName();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public void validate(){
        if(certificate.getVersion() != CERTIFICATE_VERSION_3){
            throw new CertificateException("Attestation certificate must be version 3");
        }

        String country = getSubjectCountry();
        if(country == null || country.isEmpty()){
            throw new CertificateException("Subject-C must be present");
        }
        String organization = getSubjectOrganization();
        if(organization == null || organization.isEmpty()){
            throw new CertificateException("Subject-O must be present");
        }
        String organizationUnit = getSubjectOrganizationUnit();
        if(organizationUnit == null || !organizationUnit.equals("Authenticator Attestation")){
            throw new CertificateException("Subject-OU must be present");
        }
        String commonName = getSubjectCommonName();
        if(commonName == null || commonName.isEmpty()){
            throw new CertificateException("Subject-CN must be present");
        }

        if(certificate.getBasicConstraints() != NON_CA){
            throw new CertificateException("Attestation certificate must not be CA certificate");
        }
    }

    private X500Name getX500Name() throws IOException {
        return new X500Name(certificate.getSubjectX500Principal().getName());
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
