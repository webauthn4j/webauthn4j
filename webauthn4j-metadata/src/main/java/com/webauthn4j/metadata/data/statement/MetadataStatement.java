/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This metadata statement contains a subset of verifiable information for authenticators certified by the FIDO Alliance.
 */
public class MetadataStatement implements Serializable {
    private String legalHeader;
    private String aaid;
    private String aaguid;
    private List<String> attestationCertificateKeyIdentifiers;
    private String description;
    private AlternativeDescriptions alternativeDescriptions;
    private Integer authenticatorVersion;
    private String protocolFamily;
    private List<Version> upv;
    private String assertionScheme;
    private Integer authenticationAlgorithm;
    private List<Integer> authenticationAlgorithms;
    private Integer publicKeyAlgAndEncoding;
    private List<Integer> publicKeyAlgAndEncodings;
    private List<AttestationType> attestationTypes;
    private List<VerificationMethodANDCombinations> userVerificationDetails;
    private Integer keyProtection;
    private Boolean isKeyRestricted;
    private Boolean isFreshUserVerificationRequired;
    private Integer matcherProtection;
    private Integer cryptoStrength;
    private String operationEnv;
    private BigInteger attachmentHint;
    private Boolean isSecondFactorOnly;
    private Integer tcDisplay;
    private String tcDisplayContentType;
    private List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics;
    private List<X509Certificate> attestationRootCertificates;
    private List<EcdaaTrustAnchor> ecdaaTrustAnchors;
    private String icon;
    private List<ExtensionDescriptor> supportedExtensions;

    @JsonCreator
    public MetadataStatement(
            @JsonProperty("legalHeader") String legalHeader,
            @JsonProperty("aaid") String aaid,
            @JsonProperty("aaguid") String aaguid,
            @JsonProperty("attestationCertificateKeyIdentifiers") List<String> attestationCertificateKeyIdentifiers,
            @JsonProperty("description") String description,
            @JsonProperty("alternativeDescriptions") AlternativeDescriptions alternativeDescriptions,
            @JsonProperty("authenticatorVersion") Integer authenticatorVersion,
            @JsonProperty("protocolFamily") String protocolFamily,
            @JsonProperty("upv") List<Version> upv,
            @JsonProperty("assertionScheme") String assertionScheme,
            @JsonProperty("authenticationAlgorithm") Integer authenticationAlgorithm,
            @JsonProperty("authenticationAlgorithms") List<Integer> authenticationAlgorithms,
            @JsonProperty("publicKeyAlgAndEncoding") Integer publicKeyAlgAndEncoding,
            @JsonProperty("publicKeyAlgAndEncodings") List<Integer> publicKeyAlgAndEncodings,
            @JsonProperty("attestationTypes") List<AttestationType> attestationTypes,
            @JsonProperty("userVerificationDetails") List<VerificationMethodANDCombinations> userVerificationDetails,
            @JsonProperty("keyProtection") Integer keyProtection,
            @JsonProperty("isKeyRestricted") Boolean isKeyRestricted,
            @JsonProperty("isFreshUserVerificationRequired") Boolean isFreshUserVerificationRequired,
            @JsonProperty("matcherProtection") Integer matcherProtection,
            @JsonProperty("cryptoStrength") Integer cryptoStrength,
            @JsonProperty("operationEnv") String operationEnv,
            @JsonProperty("attachmentHint") BigInteger attachmentHint,
            @JsonProperty("isSecondFactorOnly") Boolean isSecondFactorOnly,
            @JsonProperty("tcDisplay") Integer tcDisplay,
            @JsonProperty("tcDisplayContentType") String tcDisplayContentType,
            @JsonProperty("tcDisplayPNGCharacteristics") List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics,
            @JsonProperty("attestationRootCertificates") List<X509Certificate> attestationRootCertificates,
            @JsonProperty("ecdaaTrustAnchors") List<EcdaaTrustAnchor> ecdaaTrustAnchors,
            @JsonProperty("icon") String icon,
            @JsonProperty("supportedExtensions") List<ExtensionDescriptor> supportedExtensions) {
        this.legalHeader = legalHeader;
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = CollectionUtil.unmodifiableList(attestationCertificateKeyIdentifiers);
        this.alternativeDescriptions = alternativeDescriptions;
        this.authenticatorVersion = authenticatorVersion;
        this.protocolFamily = protocolFamily;
        this.upv = CollectionUtil.unmodifiableList(upv);
        this.assertionScheme = assertionScheme;
        this.authenticationAlgorithm = authenticationAlgorithm;
        this.authenticationAlgorithms = CollectionUtil.unmodifiableList(authenticationAlgorithms);
        this.publicKeyAlgAndEncoding = publicKeyAlgAndEncoding;
        this.publicKeyAlgAndEncodings = CollectionUtil.unmodifiableList(publicKeyAlgAndEncodings);
        this.attestationTypes = attestationTypes;
        this.userVerificationDetails = CollectionUtil.unmodifiableList(userVerificationDetails);
        this.keyProtection = keyProtection;
        this.isKeyRestricted = isKeyRestricted;
        this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
        this.matcherProtection = matcherProtection;
        this.cryptoStrength = cryptoStrength;
        this.operationEnv = operationEnv;
        this.attachmentHint = attachmentHint;
        this.isSecondFactorOnly = isSecondFactorOnly;
        this.tcDisplay = tcDisplay;
        this.tcDisplayContentType = tcDisplayContentType;
        this.tcDisplayPNGCharacteristics = CollectionUtil.unmodifiableList(tcDisplayPNGCharacteristics);
        this.attestationRootCertificates = CollectionUtil.unmodifiableList(attestationRootCertificates);
        this.ecdaaTrustAnchors = CollectionUtil.unmodifiableList(ecdaaTrustAnchors);
        this.icon = icon;
        this.supportedExtensions = CollectionUtil.unmodifiableList(supportedExtensions);
    }

    public String getLegalHeader() {
        return legalHeader;
    }

    public String getAaid() {
        return aaid;
    }

    public String getAaguid() {
        return aaguid;
    }

    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }

    public String getDescription() {
        return description;
    }

	public AlternativeDescriptions getAlternativeDescriptions() {
        return alternativeDescriptions;
    }

    public Integer getAuthenticatorVersion() {
        return authenticatorVersion;
    }

    public String getProtocolFamily() {
        return protocolFamily;
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

    public List<Integer> getAuthenticationAlgorithms() {
        return authenticationAlgorithms;
    }

    public Integer getPublicKeyAlgAndEncoding() {
        return publicKeyAlgAndEncoding;
    }

    public List<Integer> getPublicKeyAlgAndEncodings() {
        return publicKeyAlgAndEncodings;
    }

    public List<AttestationType> getAttestationTypes() {
        return attestationTypes;
    }

    public List<VerificationMethodANDCombinations> getUserVerificationDetails() {
        return userVerificationDetails;
    }

    public Integer getKeyProtection() {
        return keyProtection;
    }

    public Boolean getKeyRestricted() {
        return isKeyRestricted;
    }

    public Boolean getFreshUserVerificationRequired() {
        return isFreshUserVerificationRequired;
    }

    public Integer getMatcherProtection() {
        return matcherProtection;
    }

    public Integer getCryptoStrength() {
        return cryptoStrength;
    }

    public String getOperationEnv() {
        return operationEnv;
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

    public List<X509Certificate> getAttestationRootCertificates() {
        return attestationRootCertificates;
    }

    public List<EcdaaTrustAnchor> getEcdaaTrustAnchors() {
        return ecdaaTrustAnchors;
    }

    public String getIcon() {
        return icon;
    }

    public List<ExtensionDescriptor> getSupportedExtensions() {
        return supportedExtensions;
    }
}
