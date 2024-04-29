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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.converter.jackson.deserializer.json.*;
import com.webauthn4j.converter.jackson.serializer.json.*;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.deserializer.MetadataX509CertificateRelaxedDeserializer;
import com.webauthn4j.metadata.data.uaf.AAID;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * This metadata statement contains a subset of verifiable information for authenticators certified by the FIDO Alliance.
 */
public class MetadataStatement {
    @Nullable private final String legalHeader;
    @Nullable private final AAID aaid;
    @Nullable private final AAGUID aaguid;
    @Nullable private final List<String> attestationCertificateKeyIdentifiers;
    @NotNull private final String description;
    @Nullable private final AlternativeDescriptions alternativeDescriptions;
    @NotNull private final Integer authenticatorVersion;
    @NotNull private final String protocolFamily;
    @NotNull private final Integer schema;
    @NotNull private final List<Version> upv;

    @NotNull
    @JsonSerialize(contentUsing = AuthenticationAlgorithmToStringSerializer.class)
    @JsonDeserialize(contentUsing = AuthenticationAlgorithmFromStringDeserializer.class)
    private final List<AuthenticationAlgorithm> authenticationAlgorithms;

    @NotNull
    @JsonSerialize(contentUsing = PublicKeyRepresentationFormatToStringSerializer.class)
    @JsonDeserialize(contentUsing = PublicKeyRepresentationFormatFromStringDeserializer.class)
    private final List<PublicKeyRepresentationFormat> publicKeyAlgAndEncodings;

    @NotNull
    @JsonSerialize(contentUsing = AuthenticatorAttestationTypeToStringSerializer.class)
    @JsonDeserialize(contentUsing = AuthenticatorAttestationTypeFromStringDeserializer.class)
    private final List<AuthenticatorAttestationType> attestationTypes;

    @NotNull
    private final List<VerificationMethodANDCombinations> userVerificationDetails;

    @NotNull
    @JsonSerialize(contentUsing = KeyProtectionTypeToStringSerializer.class)
    @JsonDeserialize(contentUsing = KeyProtectionTypeFromStringDeserializer.class)
    private final List<KeyProtectionType> keyProtection;

    @Nullable
    private final Boolean isKeyRestricted;
    @Nullable
    private final Boolean isFreshUserVerificationRequired;

    @NotNull
    @JsonSerialize(contentUsing = MatcherProtectionTypeToStringSerializer.class)
    @JsonDeserialize(contentUsing = MatcherProtectionTypeFromStringDeserializer.class)
    private final List<MatcherProtectionType> matcherProtection;

    @Nullable
    private final Integer cryptoStrength;


    @Nullable
    @JsonSerialize(contentUsing = AttachmentHintToStringSerializer.class)
    @JsonDeserialize(contentUsing = AttachmentHintFromStringDeserializer.class)
    private final List<AttachmentHint> attachmentHint;

    @NotNull
    @JsonSerialize(contentUsing = TransactionConfirmationDisplayToStringSerializer.class)
    @JsonDeserialize(contentUsing = TransactionConfirmationDisplayFromStringDeserializer.class)
    private final List<TransactionConfirmationDisplay> tcDisplay;

    @Nullable
    private final String tcDisplayContentType;

    @Nullable
    private final List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics;

    @NotNull
    @JsonSerialize(contentUsing = X509CertificateSerializer.class)
    @JsonDeserialize(contentUsing = MetadataX509CertificateRelaxedDeserializer.class)
    private final List<X509Certificate> attestationRootCertificates;

    @Nullable
    private final List<EcdaaTrustAnchor> ecdaaTrustAnchors;
    @Nullable
    private final String icon;
    @Nullable
    private final List<ExtensionDescriptor> supportedExtensions;
    @Nullable
    private final AuthenticatorGetInfo authenticatorGetInfo;


    public MetadataStatement(
            @JsonProperty("legalHeader") @Nullable String legalHeader,
            @JsonProperty("aaid") @Nullable AAID aaid,
            @JsonProperty("aaguid") @Nullable AAGUID aaguid,
            @JsonProperty("attestationCertificateKeyIdentifiers") @Nullable List<String> attestationCertificateKeyIdentifiers,
            @JsonProperty("description") @NotNull String description,
            @JsonProperty("alternativeDescriptions") @Nullable AlternativeDescriptions alternativeDescriptions,
            @JsonProperty("authenticatorVersion") @NotNull Integer authenticatorVersion,
            @JsonProperty("protocolFamily") @NotNull String protocolFamily,
            @JsonProperty("schema") @NotNull Integer schema,
            @JsonProperty("upv") @NotNull List<Version> upv,
            @JsonProperty("authenticationAlgorithms") @NotNull List<AuthenticationAlgorithm> authenticationAlgorithms,
            @JsonProperty("publicKeyAlgAndEncodings") @NotNull List<PublicKeyRepresentationFormat> publicKeyAlgAndEncodings,
            @JsonProperty("attestationTypes") @NotNull List<AuthenticatorAttestationType> attestationTypes,
            @JsonProperty("userVerificationDetails") @NotNull List<VerificationMethodANDCombinations> userVerificationDetails,
            @JsonProperty("keyProtection") @NotNull List<KeyProtectionType> keyProtection,
            @JsonProperty("isKeyRestricted") @Nullable Boolean isKeyRestricted,
            @JsonProperty("isFreshUserVerificationRequired") @Nullable Boolean isFreshUserVerificationRequired,
            @JsonProperty("matcherProtection") @NotNull List<MatcherProtectionType> matcherProtection,
            @JsonProperty("cryptoStrength") @Nullable Integer cryptoStrength,
            @JsonProperty("attachmentHint") @Nullable List<AttachmentHint> attachmentHint,
            @JsonProperty("tcDisplay") @NotNull List<TransactionConfirmationDisplay> tcDisplay,
            @JsonProperty("tcDisplayContentType") @Nullable String tcDisplayContentType,
            @JsonProperty("tcDisplayPNGCharacteristics") @Nullable List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics,
            @JsonProperty("attestationRootCertificates") @NotNull List<X509Certificate> attestationRootCertificates,
            @JsonProperty("ecdaaTrustAnchors") @Nullable List<EcdaaTrustAnchor> ecdaaTrustAnchors,
            @JsonProperty("icon") @Nullable String icon,
            @JsonProperty("supportedExtensions") @Nullable List<ExtensionDescriptor> supportedExtensions,
            @JsonProperty("authenticatorGetInfo") @Nullable AuthenticatorGetInfo authenticatorGetInfo) {
        this.legalHeader = legalHeader;
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        this.description = description;
        this.alternativeDescriptions = alternativeDescriptions;
        this.authenticatorVersion = authenticatorVersion;
        this.protocolFamily = protocolFamily;
        this.schema = schema;
        this.upv = upv;
        this.authenticationAlgorithms = authenticationAlgorithms;
        this.publicKeyAlgAndEncodings = publicKeyAlgAndEncodings;
        this.attestationTypes = attestationTypes;
        this.userVerificationDetails = userVerificationDetails;
        this.keyProtection = keyProtection;
        this.isKeyRestricted = isKeyRestricted;
        this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
        this.matcherProtection = matcherProtection;
        this.cryptoStrength = cryptoStrength;
        this.attachmentHint = attachmentHint;
        this.tcDisplay = tcDisplay;
        this.tcDisplayContentType = tcDisplayContentType;
        this.tcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
        this.attestationRootCertificates = attestationRootCertificates;
        this.ecdaaTrustAnchors = ecdaaTrustAnchors;
        this.icon = icon;
        this.supportedExtensions = supportedExtensions;
        this.authenticatorGetInfo = authenticatorGetInfo;
    }

    @Nullable
    public String getLegalHeader() {
        return legalHeader;
    }

    @Nullable
    public AAID getAaid() {
        return aaid;
    }

    @Nullable
    public AAGUID getAaguid() {
        return aaguid;
    }

    @Nullable
    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }

    @NotNull
    public String getDescription() {
        return description;
    }

    @Nullable
    public AlternativeDescriptions getAlternativeDescriptions() {
        return alternativeDescriptions;
    }

    @NotNull
    public Integer getAuthenticatorVersion() {
        return authenticatorVersion;
    }

    @NotNull
    public String getProtocolFamily() {
        return protocolFamily;
    }

    @NotNull
    public Integer getSchema() {
        return schema;
    }

    @NotNull
    public List<Version> getUpv() {
        return upv;
    }

    @NotNull
    public List<AuthenticationAlgorithm> getAuthenticationAlgorithms() {
        return authenticationAlgorithms;
    }

    @NotNull
    public List<PublicKeyRepresentationFormat> getPublicKeyAlgAndEncodings() {
        return publicKeyAlgAndEncodings;
    }

    @NotNull
    public List<AuthenticatorAttestationType> getAttestationTypes() {
        return attestationTypes;
    }

    @NotNull
    public List<VerificationMethodANDCombinations> getUserVerificationDetails() {
        return userVerificationDetails;
    }

    @NotNull
    public List<KeyProtectionType> getKeyProtection() {
        return keyProtection;
    }

    @Nullable
    public Boolean getKeyRestricted() {
        return isKeyRestricted;
    }

    @Nullable
    public Boolean getFreshUserVerificationRequired() {
        return isFreshUserVerificationRequired;
    }

    @NotNull
    public List<MatcherProtectionType> getMatcherProtection() {
        return matcherProtection;
    }

    @Nullable
    public Integer getCryptoStrength() {
        return cryptoStrength;
    }

    @Nullable
    public List<AttachmentHint> getAttachmentHint() {
        return attachmentHint;
    }

    @NotNull
    public List<TransactionConfirmationDisplay> getTcDisplay() {
        return tcDisplay;
    }

    @Nullable
    public String getTcDisplayContentType() {
        return tcDisplayContentType;
    }

    @Nullable
    public List<DisplayPNGCharacteristicsDescriptor> getTcDisplayPNGCharacteristics() {
        return tcDisplayPNGCharacteristics;
    }

    @NotNull
    public List<X509Certificate> getAttestationRootCertificates() {
        return attestationRootCertificates;
    }

    @Nullable
    public List<EcdaaTrustAnchor> getEcdaaTrustAnchors() {
        return ecdaaTrustAnchors;
    }

    @Nullable
    public String getIcon() {
        return icon;
    }

    @Nullable
    public List<ExtensionDescriptor> getSupportedExtensions() {
        return supportedExtensions;
    }

    @Nullable
    public AuthenticatorGetInfo getAuthenticatorGetInfo() {
        return authenticatorGetInfo;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MetadataStatement that = (MetadataStatement) o;
        return Objects.equals(legalHeader, that.legalHeader) && Objects.equals(aaid, that.aaid) && Objects.equals(aaguid, that.aaguid) && Objects.equals(attestationCertificateKeyIdentifiers, that.attestationCertificateKeyIdentifiers) && description.equals(that.description) && Objects.equals(alternativeDescriptions, that.alternativeDescriptions) && authenticatorVersion.equals(that.authenticatorVersion) && protocolFamily.equals(that.protocolFamily) && schema.equals(that.schema) && upv.equals(that.upv) && authenticationAlgorithms.equals(that.authenticationAlgorithms) && publicKeyAlgAndEncodings.equals(that.publicKeyAlgAndEncodings) && attestationTypes.equals(that.attestationTypes) && userVerificationDetails.equals(that.userVerificationDetails) && keyProtection.equals(that.keyProtection) && Objects.equals(isKeyRestricted, that.isKeyRestricted) && Objects.equals(isFreshUserVerificationRequired, that.isFreshUserVerificationRequired) && matcherProtection.equals(that.matcherProtection) && Objects.equals(cryptoStrength, that.cryptoStrength) && Objects.equals(attachmentHint, that.attachmentHint) && tcDisplay.equals(that.tcDisplay) && Objects.equals(tcDisplayContentType, that.tcDisplayContentType) && Objects.equals(tcDisplayPNGCharacteristics, that.tcDisplayPNGCharacteristics) && attestationRootCertificates.equals(that.attestationRootCertificates) && Objects.equals(ecdaaTrustAnchors, that.ecdaaTrustAnchors) && Objects.equals(icon, that.icon) && Objects.equals(supportedExtensions, that.supportedExtensions) && Objects.equals(authenticatorGetInfo, that.authenticatorGetInfo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, description, alternativeDescriptions, authenticatorVersion, protocolFamily, schema, upv, authenticationAlgorithms, publicKeyAlgAndEncodings, attestationTypes, userVerificationDetails, keyProtection, isKeyRestricted, isFreshUserVerificationRequired, matcherProtection, cryptoStrength, attachmentHint, tcDisplay, tcDisplayContentType, tcDisplayPNGCharacteristics, attestationRootCertificates, ecdaaTrustAnchors, icon, supportedExtensions, authenticatorGetInfo);
    }
}
