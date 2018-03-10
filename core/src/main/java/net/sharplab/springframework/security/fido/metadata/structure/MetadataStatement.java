package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Created by ynojima on 2017/09/08.
 */
public class MetadataStatement {
    @JsonProperty
    private String aaid;
    @JsonProperty
    private String title;
    @JsonProperty
    private String description;
    @JsonProperty
    private Integer authenticatorVersion;
    @JsonProperty
    private List<Version> upv;
    @JsonProperty
    private String assertionScheme;
    @JsonProperty
    private Integer authenticationAlgorithm;
    @JsonProperty
    private Integer publicKeyAlgAndEncoding;
    @JsonProperty
    private List<Integer> attestationTypes;
    @JsonProperty
    private List<List<VerificationMethodDescriptor>> userVerificationDetails;
    @JsonProperty
    private Integer keyProtection;
    @JsonProperty
    private Integer matcherProtection;
    @JsonProperty
    private BigInteger attachmentHint;
    @JsonProperty
    private Boolean isSecondFactorOnly;
    @JsonProperty
    private Integer tcDisplay;
    @JsonProperty
    private String tcDisplayContentType;
    @JsonProperty
    private List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics;
    @JsonProperty
    private List<String> attestationCertificateKeyIdentifiers;
    @JsonProperty
    private List<X509Certificate> attestationRootCertificates;
    @JsonProperty
    private String icon;
    @JsonProperty
    private String imagePngContentType;
    @JsonProperty
    private String protocolFamily;

    public String getAaid() {
        return aaid;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public Integer getAuthenticatorVersion() {
        return authenticatorVersion;
    }

    public List<Version> getUpv() {
        return upv;
    }

    public String getAssertionScheme() {
        return assertionScheme;
    }

    public Integer getAuthenticationAlgorithm() {
        return authenticationAlgorithm;
    }

    public Integer getPublicKeyAlgAndEncoding() {
        return publicKeyAlgAndEncoding;
    }

    public List<Integer> getAttestationTypes() {
        return attestationTypes;
    }

    public List<List<VerificationMethodDescriptor>> getUserVerificationDetails() {
        return userVerificationDetails;
    }

    public Integer getKeyProtection() {
        return keyProtection;
    }

    public Integer getMatcherProtection() {
        return matcherProtection;
    }

    public BigInteger getAttachmentHint() {
        return attachmentHint;
    }

    public Boolean getSecondFactorOnly() {
        return isSecondFactorOnly;
    }

    public Integer getTcDisplay() {
        return tcDisplay;
    }

    public String getTcDisplayContentType() {
        return tcDisplayContentType;
    }

    public List<DisplayPNGCharacteristicsDescriptor> getTcDisplayPNGCharacteristics() {
        return tcDisplayPNGCharacteristics;
    }

    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }

    public List<X509Certificate> getAttestationRootCertificates() {
        return attestationRootCertificates;
    }

    public String getIcon() {
        return icon;
    }

    public String getImagePngContentType() {
        return imagePngContentType;
    }

    public String getProtocolFamily() {
        return protocolFamily;
    }
}
