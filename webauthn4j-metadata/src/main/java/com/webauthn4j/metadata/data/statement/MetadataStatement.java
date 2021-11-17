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
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.converter.jackson.deserializer.json.*;
import com.webauthn4j.converter.jackson.serializer.json.*;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.deserializer.MetadataX509CertificateRelaxedDeserializer;
import com.webauthn4j.metadata.data.uaf.AAID;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This metadata statement contains a subset of verifiable information for authenticators certified by the FIDO Alliance.
 */
public class MetadataStatement implements Serializable {
    private final String legalHeader;
    private final AAID aaid;
    private final AAGUID aaguid;
    private final List<String> attestationCertificateKeyIdentifiers;
    private final String description;
    private final AlternativeDescriptions alternativeDescriptions;
    private final Integer authenticatorVersion;
    private final String protocolFamily;
    private final List<Version> upv;
    private final String assertionScheme;
    private final AuthenticationAlgorithm authenticationAlgorithm;

    @JsonSerialize(contentUsing = AuthenticationAlgorithmToStringSerializer.class)
    @JsonDeserialize(contentUsing = AuthenticationAlgorithmFromStringDeserializer.class)
    private final List<AuthenticationAlgorithm> authenticationAlgorithms;
    private final PublicKeyRepresentationFormat publicKeyAlgAndEncoding;

    @JsonSerialize(contentUsing = PublicKeyRepresentationFormatToStringSerializer.class)
    @JsonDeserialize(contentUsing = PublicKeyRepresentationFormatFromStringDeserializer.class)
    private final List<PublicKeyRepresentationFormat> publicKeyAlgAndEncodings;

    @JsonSerialize(contentUsing = AuthenticatorAttestationTypeToStringSerializer.class)
    @JsonDeserialize(contentUsing = AuthenticatorAttestationTypeFromStringDeserializer.class)
    private final List<AuthenticatorAttestationType> attestationTypes;
    private final List<VerificationMethodANDCombinations> userVerificationDetails;

    @JsonSerialize(contentUsing = KeyProtectionTypeToStringSerializer.class)
    @JsonDeserialize(contentUsing = KeyProtectionTypeFromStringDeserializer.class)
    private final List<KeyProtectionType> keyProtection;
    private final Boolean isKeyRestricted;
    private final Boolean isFreshUserVerificationRequired;

    @JsonSerialize(contentUsing = MatcherProtectionTypeToStringSerializer.class)
    @JsonDeserialize(contentUsing = MatcherProtectionTypeFromStringDeserializer.class)
    private final List<MatcherProtectionType> matcherProtection;

    private final Integer cryptoStrength;
    private final String operationEnv;

    @JsonSerialize(contentUsing = AttachmentHintToStringSerializer.class)
    @JsonDeserialize(contentUsing = AttachmentHintFromStringDeserializer.class)
    private final List<AttachmentHint> attachmentHint;

    private final Boolean isSecondFactorOnly;

    @JsonSerialize(contentUsing = TransactionConfirmationDisplayToStringSerializer.class)
    @JsonDeserialize(contentUsing = TransactionConfirmationDisplayFromStringDeserializer.class)
    private final List<TransactionConfirmationDisplay> tcDisplay;

    private final String tcDisplayContentType;
    private final List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics;

    @JsonSerialize(contentUsing = X509CertificateSerializer.class)
    @JsonDeserialize(contentUsing = MetadataX509CertificateRelaxedDeserializer.class)
    private final List<X509Certificate> attestationRootCertificates;
    private final List<EcdaaTrustAnchor> ecdaaTrustAnchors;
    private final String icon;
    private final List<ExtensionDescriptor> supportedExtensions;

    @JsonCreator
    public MetadataStatement(
            @JsonProperty("legalHeader") String legalHeader,
            @JsonProperty("aaid") AAID aaid,
            @JsonProperty("aaguid") AAGUID aaguid,
            @JsonProperty("attestationCertificateKeyIdentifiers") List<String> attestationCertificateKeyIdentifiers,
            @JsonProperty("description") String description,
            @JsonProperty("alternativeDescriptions") AlternativeDescriptions alternativeDescriptions,
            @JsonProperty("authenticatorVersion") Integer authenticatorVersion,
            @JsonProperty("protocolFamily") String protocolFamily,
            @JsonProperty("upv") List<Version> upv,
            @JsonProperty("assertionScheme") String assertionScheme,
            @JsonProperty("authenticationAlgorithm") AuthenticationAlgorithm authenticationAlgorithm,
            @JsonProperty("authenticationAlgorithms") List<AuthenticationAlgorithm> authenticationAlgorithms,
            @JsonProperty("publicKeyAlgAndEncoding") PublicKeyRepresentationFormat publicKeyAlgAndEncoding,
            @JsonProperty("publicKeyAlgAndEncodings") List<PublicKeyRepresentationFormat> publicKeyAlgAndEncodings,
            @JsonProperty("attestationTypes") List<AuthenticatorAttestationType> attestationTypes,
            @JsonProperty("userVerificationDetails") List<VerificationMethodANDCombinations> userVerificationDetails,
            @JsonProperty("keyProtection") List<KeyProtectionType> keyProtection,
            @JsonProperty("isKeyRestricted") Boolean isKeyRestricted,
            @JsonProperty("isFreshUserVerificationRequired") Boolean isFreshUserVerificationRequired,
            @JsonProperty("matcherProtection") List<MatcherProtectionType> matcherProtection,
            @JsonProperty("cryptoStrength") Integer cryptoStrength,
            @JsonProperty("operationEnv") String operationEnv,
            @JsonProperty("attachmentHint") List<AttachmentHint> attachmentHint,
            @JsonProperty("isSecondFactorOnly") Boolean isSecondFactorOnly,
            @JsonProperty("tcDisplay") List<TransactionConfirmationDisplay> tcDisplay,
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
        this.description = description;
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

    public AAID getAaid() {
        return aaid;
    }

    public AAGUID getAaguid() {
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

    public AuthenticationAlgorithm getAuthenticationAlgorithm() {
        return authenticationAlgorithm;
    }

    public List<AuthenticationAlgorithm> getAuthenticationAlgorithms() {
        return authenticationAlgorithms;
    }

    public PublicKeyRepresentationFormat getPublicKeyAlgAndEncoding() {
        return publicKeyAlgAndEncoding;
    }

    public List<PublicKeyRepresentationFormat> getPublicKeyAlgAndEncodings() {
        return publicKeyAlgAndEncodings;
    }

    public List<AuthenticatorAttestationType> getAttestationTypes() {
        return attestationTypes;
    }

    public List<VerificationMethodANDCombinations> getUserVerificationDetails() {
        return userVerificationDetails;
    }

    public List<KeyProtectionType> getKeyProtection() {
        return keyProtection;
    }

    public Boolean getKeyRestricted() {
        return isKeyRestricted;
    }

    public Boolean getFreshUserVerificationRequired() {
        return isFreshUserVerificationRequired;
    }

    public List<MatcherProtectionType> getMatcherProtection() {
        return matcherProtection;
    }

    public Integer getCryptoStrength() {
        return cryptoStrength;
    }

    public String getOperationEnv() {
        return operationEnv;
    }

    public List<AttachmentHint> getAttachmentHint() {
        return attachmentHint;
    }

    public Boolean getSecondFactorOnly() {
        return isSecondFactorOnly;
    }

    public List<TransactionConfirmationDisplay> getTcDisplay() {
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
