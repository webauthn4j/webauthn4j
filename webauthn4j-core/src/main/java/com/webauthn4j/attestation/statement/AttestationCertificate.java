package com.webauthn4j.attestation.statement;

import com.webauthn4j.validator.exception.CertificateException;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;


public class AttestationCertificate {

    private static final int CERTIFICATE_VERSION_3 = 3;
    private static final int NON_CA = -1;
    private X509Certificate certificate;

    public AttestationCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getSubjectCountry() {
        return getValue("C");
    }

    public String getSubjectOrganization() {
        return getValue("O");
    }

    public String getSubjectOrganizationUnit() {
        return getValue("OU");
    }

    public String getSubjectCommonName() {
        return getValue("CN");
    }

    public void validate() {
        if (certificate.getVersion() != CERTIFICATE_VERSION_3) {
            throw new CertificateException("Attestation certificate must be version 3");
        }

        String country = getSubjectCountry();
        if (country == null || country.isEmpty()) {
            throw new CertificateException("Subject-C must be present");
        }
        String organization = getSubjectOrganization();
        if (organization == null || organization.isEmpty()) {
            throw new CertificateException("Subject-O must be present");
        }
        String organizationUnit = getSubjectOrganizationUnit();
        if (organizationUnit == null || !organizationUnit.equals("Authenticator Attestation")) {
            throw new CertificateException("Subject-OU must be present");
        }
        String commonName = getSubjectCommonName();
        if (commonName == null || commonName.isEmpty()) {
            throw new CertificateException("Subject-CN must be present");
        }

        if (certificate.getBasicConstraints() != NON_CA) {
            throw new CertificateException("Attestation certificate must not be CA certificate");
        }
    }

    private List<Rdn> getX500Name() {
        String subjectDN = getCertificate().getSubjectX500Principal().getName();
        try {
            return new LdapName(subjectDN).getRdns();
        } catch (InvalidNameException e) {
            throw new CertificateException("invalid subjectDN: " + subjectDN);
        }
    }

    private String getValue(String name){
        for (Rdn rdn : getX500Name()) {
            if(rdn.getType().equalsIgnoreCase(name)){
                return (String)rdn.getValue();
            }
        }
        return null;
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
