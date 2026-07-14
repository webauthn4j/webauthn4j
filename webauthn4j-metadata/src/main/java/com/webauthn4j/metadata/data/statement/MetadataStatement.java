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
import com.webauthn4j.converter.jackson.deserializer.json.*;
import com.webauthn4j.converter.jackson.serializer.json.*;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.CollectionUtil;
import com.webauthn4j.metadata.converter.jackson.deserializer.MetadataX509CertificateRelaxedDeserializer;
import com.webauthn4j.metadata.data.uaf.AAID;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * This metadata statement contains a subset of verifiable information for authenticators certified by the FIDO Alliance.
 *
 * @see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#dictdef-metadatastatement">Metadata Statement v3.1.1</a>
 */
public class MetadataStatement {
    @Nullable private final String legalHeader;
    @Nullable private final AAID aaid;
    @Nullable private final AAGUID aaguid;
    @Nullable private final List<String> attestationCertificateKeyIdentifiers;
    @Nullable private final FriendlyNames friendlyNames;
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
    private final String iconDark;
    @Nullable
    private final String providerLogoLight;
    @Nullable
    private final String providerLogoDark;
    @Nullable
    private final List<ExtensionDescriptor> supportedExtensions;
    @Nullable
    private final MultiDeviceCredentialSupport multiDeviceCredentialSupport;
    @Nullable
    private final AuthenticatorGetInfo authenticatorGetInfo;
    @Nullable
    private final String cxConfigURL;

    @SuppressWarnings("java:S107")
    public MetadataStatement(
            @JsonProperty("legalHeader") @Nullable String legalHeader,
            @JsonProperty("aaid") @Nullable AAID aaid,
            @JsonProperty("aaguid") @Nullable AAGUID aaguid,
            @JsonProperty("attestationCertificateKeyIdentifiers") @Nullable List<String> attestationCertificateKeyIdentifiers,
            @JsonProperty("friendlyNames") @Nullable FriendlyNames friendlyNames,
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
            @JsonProperty("iconDark") @Nullable String iconDark,
            @JsonProperty("providerLogoLight") @Nullable String providerLogoLight,
            @JsonProperty("providerLogoDark") @Nullable String providerLogoDark,
            @JsonProperty("supportedExtensions") @Nullable List<ExtensionDescriptor> supportedExtensions,
            @JsonProperty("multiDeviceCredentialSupport") @Nullable MultiDeviceCredentialSupport multiDeviceCredentialSupport,
            @JsonProperty("authenticatorGetInfo") @Nullable AuthenticatorGetInfo authenticatorGetInfo,
            @JsonProperty("cxConfigURL") @Nullable String cxConfigURL) {
        this.legalHeader = legalHeader;
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = CollectionUtil.unmodifiableList(attestationCertificateKeyIdentifiers);
        this.friendlyNames = friendlyNames;
        this.description = description;
        this.alternativeDescriptions = alternativeDescriptions;
        this.authenticatorVersion = authenticatorVersion;
        this.protocolFamily = protocolFamily;
        this.schema = schema;
        this.upv = CollectionUtil.unmodifiableList(upv);
        this.authenticationAlgorithms = CollectionUtil.unmodifiableList(authenticationAlgorithms);
        this.publicKeyAlgAndEncodings = CollectionUtil.unmodifiableList(publicKeyAlgAndEncodings);
        this.attestationTypes = CollectionUtil.unmodifiableList(attestationTypes);
        this.userVerificationDetails = CollectionUtil.unmodifiableList(userVerificationDetails);
        this.keyProtection = CollectionUtil.unmodifiableList(keyProtection);
        this.isKeyRestricted = isKeyRestricted;
        this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
        this.matcherProtection = CollectionUtil.unmodifiableList(matcherProtection);
        this.cryptoStrength = cryptoStrength;
        this.attachmentHint = CollectionUtil.unmodifiableList(attachmentHint);
        this.tcDisplay = CollectionUtil.unmodifiableList(tcDisplay);
        this.tcDisplayContentType = tcDisplayContentType;
        this.tcDisplayPNGCharacteristics = CollectionUtil.unmodifiableList(tcDisplayPNGCharacteristics);
        this.attestationRootCertificates = CollectionUtil.unmodifiableList(attestationRootCertificates);
        this.ecdaaTrustAnchors = CollectionUtil.unmodifiableList(ecdaaTrustAnchors);
        this.icon = icon;
        this.iconDark = iconDark;
        this.providerLogoLight = providerLogoLight;
        this.providerLogoDark = providerLogoDark;
        this.supportedExtensions = CollectionUtil.unmodifiableList(supportedExtensions);
        this.multiDeviceCredentialSupport = multiDeviceCredentialSupport;
        this.authenticatorGetInfo = authenticatorGetInfo;
        this.cxConfigURL = cxConfigURL;
    }

    /**
     * @deprecated Use the full constructor instead.
     */
    @Deprecated
    public MetadataStatement(
            @Nullable String legalHeader,
            @Nullable AAID aaid,
            @Nullable AAGUID aaguid,
            @Nullable List<String> attestationCertificateKeyIdentifiers,
            @NotNull String description,
            @Nullable AlternativeDescriptions alternativeDescriptions,
            @NotNull Integer authenticatorVersion,
            @NotNull String protocolFamily,
            @NotNull Integer schema,
            @NotNull List<Version> upv,
            @NotNull List<AuthenticationAlgorithm> authenticationAlgorithms,
            @NotNull List<PublicKeyRepresentationFormat> publicKeyAlgAndEncodings,
            @NotNull List<AuthenticatorAttestationType> attestationTypes,
            @NotNull List<VerificationMethodANDCombinations> userVerificationDetails,
            @NotNull List<KeyProtectionType> keyProtection,
            @Nullable Boolean isKeyRestricted,
            @Nullable Boolean isFreshUserVerificationRequired,
            @NotNull List<MatcherProtectionType> matcherProtection,
            @Nullable Integer cryptoStrength,
            @Nullable List<AttachmentHint> attachmentHint,
            @NotNull List<TransactionConfirmationDisplay> tcDisplay,
            @Nullable String tcDisplayContentType,
            @Nullable List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics,
            @NotNull List<X509Certificate> attestationRootCertificates,
            @Nullable List<EcdaaTrustAnchor> ecdaaTrustAnchors,
            @Nullable String icon,
            @Nullable List<ExtensionDescriptor> supportedExtensions,
            @Nullable AuthenticatorGetInfo authenticatorGetInfo) {
        this(legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, null,
                description, alternativeDescriptions, authenticatorVersion, protocolFamily, schema,
                upv, authenticationAlgorithms, publicKeyAlgAndEncodings, attestationTypes,
                userVerificationDetails, keyProtection, isKeyRestricted, isFreshUserVerificationRequired,
                matcherProtection, cryptoStrength, attachmentHint, tcDisplay, tcDisplayContentType,
                tcDisplayPNGCharacteristics, attestationRootCertificates, ecdaaTrustAnchors,
                icon, null, null, null, supportedExtensions, null, authenticatorGetInfo, null);
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

    @Nullable
    public FriendlyNames getFriendlyNames() {
        return friendlyNames;
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
    public String getIconDark() {
        return iconDark;
    }

    @Nullable
    public String getProviderLogoLight() {
        return providerLogoLight;
    }

    @Nullable
    public String getProviderLogoDark() {
        return providerLogoDark;
    }

    @Nullable
    public List<ExtensionDescriptor> getSupportedExtensions() {
        return supportedExtensions;
    }

    @Nullable
    public MultiDeviceCredentialSupport getMultiDeviceCredentialSupport() {
        return multiDeviceCredentialSupport;
    }

    @Nullable
    public AuthenticatorGetInfo getAuthenticatorGetInfo() {
        return authenticatorGetInfo;
    }

    @Nullable
    public String getCxConfigURL() {
        return cxConfigURL;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MetadataStatement that = (MetadataStatement) o;
        return Objects.equals(legalHeader, that.legalHeader) && Objects.equals(aaid, that.aaid) && Objects.equals(aaguid, that.aaguid) && Objects.equals(attestationCertificateKeyIdentifiers, that.attestationCertificateKeyIdentifiers) && Objects.equals(friendlyNames, that.friendlyNames) && description.equals(that.description) && Objects.equals(alternativeDescriptions, that.alternativeDescriptions) && authenticatorVersion.equals(that.authenticatorVersion) && protocolFamily.equals(that.protocolFamily) && schema.equals(that.schema) && upv.equals(that.upv) && authenticationAlgorithms.equals(that.authenticationAlgorithms) && publicKeyAlgAndEncodings.equals(that.publicKeyAlgAndEncodings) && attestationTypes.equals(that.attestationTypes) && userVerificationDetails.equals(that.userVerificationDetails) && keyProtection.equals(that.keyProtection) && Objects.equals(isKeyRestricted, that.isKeyRestricted) && Objects.equals(isFreshUserVerificationRequired, that.isFreshUserVerificationRequired) && matcherProtection.equals(that.matcherProtection) && Objects.equals(cryptoStrength, that.cryptoStrength) && Objects.equals(attachmentHint, that.attachmentHint) && tcDisplay.equals(that.tcDisplay) && Objects.equals(tcDisplayContentType, that.tcDisplayContentType) && Objects.equals(tcDisplayPNGCharacteristics, that.tcDisplayPNGCharacteristics) && attestationRootCertificates.equals(that.attestationRootCertificates) && Objects.equals(ecdaaTrustAnchors, that.ecdaaTrustAnchors) && Objects.equals(icon, that.icon) && Objects.equals(iconDark, that.iconDark) && Objects.equals(providerLogoLight, that.providerLogoLight) && Objects.equals(providerLogoDark, that.providerLogoDark) && Objects.equals(supportedExtensions, that.supportedExtensions) && Objects.equals(multiDeviceCredentialSupport, that.multiDeviceCredentialSupport) && Objects.equals(authenticatorGetInfo, that.authenticatorGetInfo) && Objects.equals(cxConfigURL, that.cxConfigURL);
    }

    @Override
    public int hashCode() {
        return Objects.hash(legalHeader, aaid, aaguid, attestationCertificateKeyIdentifiers, friendlyNames, description, alternativeDescriptions, authenticatorVersion, protocolFamily, schema, upv, authenticationAlgorithms, publicKeyAlgAndEncodings, attestationTypes, userVerificationDetails, keyProtection, isKeyRestricted, isFreshUserVerificationRequired, matcherProtection, cryptoStrength, attachmentHint, tcDisplay, tcDisplayContentType, tcDisplayPNGCharacteristics, attestationRootCertificates, ecdaaTrustAnchors, icon, iconDark, providerLogoLight, providerLogoDark, supportedExtensions, multiDeviceCredentialSupport, authenticatorGetInfo, cxConfigURL);
    }
}
