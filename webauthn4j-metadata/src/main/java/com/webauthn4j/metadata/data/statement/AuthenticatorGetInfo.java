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

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PinProtocolVersion;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.deserializer.MetadataAAGUIDRelaxedDeserializer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.annotation.JsonDeserialize;


import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@SuppressWarnings("java:S107")
public class AuthenticatorGetInfo {

    @JsonProperty("versions")
    @NotNull
    private final List<String> versions;

    @JsonProperty("extensions")
    @Nullable
    private final List<String> extensions;

    @JsonProperty("aaguid")
    @NotNull
    @JsonDeserialize(using = MetadataAAGUIDRelaxedDeserializer.class)
    private final AAGUID aaguid;

    @JsonProperty("options")
    @Nullable
    private final Options options;

    @JsonProperty("maxMsgSize")
    @Nullable
    private final Integer maxMsgSize;

    @JsonProperty("pinUvAuthProtocols")
    @Nullable
    private final List<PinProtocolVersion> pinUvAuthProtocols;

    @JsonProperty("maxCredentialCountInList")
    @Nullable
    private final Integer maxCredentialCountInList;

    @JsonProperty("maxCredentialIdLength")
    @Nullable
    private final Integer maxCredentialIdLength;

    @JsonProperty("transports")
    @Nullable
    private final List<AuthenticatorTransport> transports;

    @JsonProperty("algorithms")
    @Nullable
    private final List<PublicKeyCredentialParameters> algorithms;

    @JsonProperty("maxSerializedLargeBlobArray")
    @Nullable
    private final Integer maxSerializedLargeBlobArray;

    @JsonProperty("forcePINChange")
    @Nullable
    private final Boolean forcePINChange;

    @JsonProperty("minPINLength")
    @Nullable
    private final Integer minPINLength;

    @JsonProperty("firmwareVersion")
    @Nullable
    private final Integer firmwareVersion;

    @JsonProperty("maxCredBlobLength")
    @Nullable
    private final Integer maxCredBlobLength;

    @JsonProperty("maxRPIDsForSetMinPINLength")
    @Nullable
    private final Integer maxRPIDsForSetMinPINLength;

    @JsonProperty("preferredPlatformUvAttempts")
    @Nullable
    private final Integer preferredPlatformUvAttempts;

    @JsonProperty("uvModality")
    @Nullable
    private final Set<UserVerificationMethod> uvModality;

    @JsonProperty("certifications")
    @Nullable
    private final Map<String, Object> certifications;

    @JsonProperty("remainingDiscoverableCredentials")
    @Nullable
    private final Integer remainingDiscoverableCredentials;

    @JsonProperty("vendorPrototypeConfigCommands")
    @Nullable
    private final List<Integer> vendorPrototypeConfigCommands;

    @JsonProperty("attestationFormats")
    @Nullable
    private final List<String> attestationFormats;

    @JsonProperty("uvCountSinceLastPinEntry")
    @Nullable
    private final Integer uvCountSinceLastPinEntry;

    @JsonProperty("longTouchForReset")
    @Nullable
    private final Boolean longTouchForReset;

    @JsonProperty("encIdentifier")
    @Nullable
    private final String encIdentifier;

    @JsonProperty("transportsForReset")
    @Nullable
    private final List<AuthenticatorTransport> transportsForReset;

    @JsonProperty("pinComplexityPolicy")
    @Nullable
    private final Boolean pinComplexityPolicy;

    @JsonProperty("pinComplexityPolicyURL")
    @Nullable
    private final String pinComplexityPolicyURL;

    @JsonProperty("maxPINLength")
    @Nullable
    private final Integer maxPINLength;

    @JsonProperty("encCredStoreState")
    @Nullable
    private final String encCredStoreState;

    @JsonProperty("authenticatorConfigCommands")
    @Nullable
    private final List<Integer> authenticatorConfigCommands;

    @JsonCreator
    public AuthenticatorGetInfo(
            @JsonProperty("versions") @NotNull List<String> versions,
            @JsonProperty("extensions") @Nullable List<String> extensions,
            @JsonProperty("aaguid") @NotNull AAGUID aaguid,
            @JsonProperty("options") @Nullable Options options,
            @JsonProperty("maxMsgSize") @Nullable Integer maxMsgSize,
            @JsonProperty("pinUvAuthProtocols") @Nullable List<PinProtocolVersion> pinUvAuthProtocols,
            @JsonProperty("maxCredentialCountInList") @Nullable Integer maxCredentialCountInList,
            @JsonProperty("maxCredentialIdLength") @Nullable Integer maxCredentialIdLength,
            @JsonProperty("transports") @Nullable List<AuthenticatorTransport> transports,
            @JsonProperty("algorithms") @Nullable List<PublicKeyCredentialParameters> algorithms,
            @JsonProperty("maxSerializedLargeBlobArray") @Nullable Integer maxSerializedLargeBlobArray,
            @JsonProperty("forcePINChange") @Nullable Boolean forcePINChange,
            @JsonProperty("minPINLength") @Nullable Integer minPINLength,
            @JsonProperty("firmwareVersion") @Nullable Integer firmwareVersion,
            @JsonProperty("maxCredBlobLength") @Nullable Integer maxCredBlobLength,
            @JsonProperty("maxRPIDsForSetMinPINLength") @Nullable Integer maxRPIDsForSetMinPINLength,
            @JsonProperty("preferredPlatformUvAttempts") @Nullable Integer preferredPlatformUvAttempts,
            @JsonProperty("uvModality") @Nullable Set<UserVerificationMethod> uvModality,
            @JsonProperty("certifications") @Nullable Map<String, Object> certifications,
            @JsonProperty("remainingDiscoverableCredentials") @Nullable Integer remainingDiscoverableCredentials,
            @JsonProperty("vendorPrototypeConfigCommands") @Nullable List<Integer> vendorPrototypeConfigCommands,
            @JsonProperty("attestationFormats") @Nullable List<String> attestationFormats,
            @JsonProperty("uvCountSinceLastPinEntry") @Nullable Integer uvCountSinceLastPinEntry,
            @JsonProperty("longTouchForReset") @Nullable Boolean longTouchForReset,
            @JsonProperty("encIdentifier") @Nullable String encIdentifier,
            @JsonProperty("transportsForReset") @Nullable List<AuthenticatorTransport> transportsForReset,
            @JsonProperty("pinComplexityPolicy") @Nullable Boolean pinComplexityPolicy,
            @JsonProperty("pinComplexityPolicyURL") @Nullable String pinComplexityPolicyURL,
            @JsonProperty("maxPINLength") @Nullable Integer maxPINLength,
            @JsonProperty("encCredStoreState") @Nullable String encCredStoreState,
            @JsonProperty("authenticatorConfigCommands") @Nullable List<Integer> authenticatorConfigCommands) {
        this.versions = versions;
        this.extensions = extensions;
        this.aaguid = aaguid;
        this.options = options;
        this.maxMsgSize = maxMsgSize;
        this.pinUvAuthProtocols = pinUvAuthProtocols;
        this.maxCredentialCountInList = maxCredentialCountInList;
        this.maxCredentialIdLength = maxCredentialIdLength;
        this.transports = transports;
        this.algorithms = algorithms;
        this.maxSerializedLargeBlobArray = maxSerializedLargeBlobArray;
        this.forcePINChange = forcePINChange;
        this.minPINLength = minPINLength;
        this.firmwareVersion = firmwareVersion;
        this.maxCredBlobLength = maxCredBlobLength;
        this.maxRPIDsForSetMinPINLength = maxRPIDsForSetMinPINLength;
        this.preferredPlatformUvAttempts = preferredPlatformUvAttempts;
        this.uvModality = uvModality;
        this.certifications = certifications;
        this.remainingDiscoverableCredentials = remainingDiscoverableCredentials;
        this.vendorPrototypeConfigCommands = vendorPrototypeConfigCommands;
        this.attestationFormats = attestationFormats;
        this.uvCountSinceLastPinEntry = uvCountSinceLastPinEntry;
        this.longTouchForReset = longTouchForReset;
        this.encIdentifier = encIdentifier;
        this.transportsForReset = transportsForReset;
        this.pinComplexityPolicy = pinComplexityPolicy;
        this.pinComplexityPolicyURL = pinComplexityPolicyURL;
        this.maxPINLength = maxPINLength;
        this.encCredStoreState = encCredStoreState;
        this.authenticatorConfigCommands = authenticatorConfigCommands;
    }

    @Deprecated
    public AuthenticatorGetInfo(
            @NotNull List<String> versions,
            @Nullable List<String> extensions,
            @NotNull AAGUID aaguid,
            @Nullable Options options,
            @Nullable Integer maxMsgSize,
            @Nullable List<PinProtocolVersion> pinUvAuthProtocols) {
        this(versions, extensions, aaguid, options, maxMsgSize, pinUvAuthProtocols,
                null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null);
    }

    public @NotNull List<String> getVersions() {
        return versions;
    }

    public @Nullable List<String> getExtensions() {
        return extensions;
    }

    public @NotNull AAGUID getAaguid() {
        return aaguid;
    }

    public @Nullable Options getOptions() {
        return options;
    }

    public @Nullable Integer getMaxMsgSize() {
        return maxMsgSize;
    }

    public @Nullable List<PinProtocolVersion> getPinUvAuthProtocols() {
        return pinUvAuthProtocols;
    }

    public @Nullable Integer getMaxCredentialCountInList() {
        return maxCredentialCountInList;
    }

    public @Nullable Integer getMaxCredentialIdLength() {
        return maxCredentialIdLength;
    }

    public @Nullable List<AuthenticatorTransport> getTransports() {
        return transports;
    }

    public @Nullable List<PublicKeyCredentialParameters> getAlgorithms() {
        return algorithms;
    }

    public @Nullable Integer getMaxSerializedLargeBlobArray() {
        return maxSerializedLargeBlobArray;
    }

    public @Nullable Boolean getForcePINChange() {
        return forcePINChange;
    }

    public @Nullable Integer getMinPINLength() {
        return minPINLength;
    }

    public @Nullable Integer getFirmwareVersion() {
        return firmwareVersion;
    }

    public @Nullable Integer getMaxCredBlobLength() {
        return maxCredBlobLength;
    }

    public @Nullable Integer getMaxRPIDsForSetMinPINLength() {
        return maxRPIDsForSetMinPINLength;
    }

    public @Nullable Integer getPreferredPlatformUvAttempts() {
        return preferredPlatformUvAttempts;
    }

    public @Nullable Set<UserVerificationMethod> getUvModality() {
        return uvModality;
    }

    public @Nullable Map<String, Object> getCertifications() {
        return certifications;
    }

    public @Nullable Integer getRemainingDiscoverableCredentials() {
        return remainingDiscoverableCredentials;
    }

    public @Nullable List<Integer> getVendorPrototypeConfigCommands() {
        return vendorPrototypeConfigCommands;
    }

    public @Nullable List<String> getAttestationFormats() {
        return attestationFormats;
    }

    public @Nullable Integer getUvCountSinceLastPinEntry() {
        return uvCountSinceLastPinEntry;
    }

    public @Nullable Boolean getLongTouchForReset() {
        return longTouchForReset;
    }

    public @Nullable String getEncIdentifier() {
        return encIdentifier;
    }

    public @Nullable List<AuthenticatorTransport> getTransportsForReset() {
        return transportsForReset;
    }

    public @Nullable Boolean getPinComplexityPolicy() {
        return pinComplexityPolicy;
    }

    public @Nullable String getPinComplexityPolicyURL() {
        return pinComplexityPolicyURL;
    }

    public @Nullable Integer getMaxPINLength() {
        return maxPINLength;
    }

    public @Nullable String getEncCredStoreState() {
        return encCredStoreState;
    }

    public @Nullable List<Integer> getAuthenticatorConfigCommands() {
        return authenticatorConfigCommands;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorGetInfo that = (AuthenticatorGetInfo) o;
        return versions.equals(that.versions) &&
                Objects.equals(extensions, that.extensions) &&
                aaguid.equals(that.aaguid) &&
                Objects.equals(options, that.options) &&
                Objects.equals(maxMsgSize, that.maxMsgSize) &&
                Objects.equals(pinUvAuthProtocols, that.pinUvAuthProtocols) &&
                Objects.equals(maxCredentialCountInList, that.maxCredentialCountInList) &&
                Objects.equals(maxCredentialIdLength, that.maxCredentialIdLength) &&
                Objects.equals(transports, that.transports) &&
                Objects.equals(algorithms, that.algorithms) &&
                Objects.equals(maxSerializedLargeBlobArray, that.maxSerializedLargeBlobArray) &&
                Objects.equals(forcePINChange, that.forcePINChange) &&
                Objects.equals(minPINLength, that.minPINLength) &&
                Objects.equals(firmwareVersion, that.firmwareVersion) &&
                Objects.equals(maxCredBlobLength, that.maxCredBlobLength) &&
                Objects.equals(maxRPIDsForSetMinPINLength, that.maxRPIDsForSetMinPINLength) &&
                Objects.equals(preferredPlatformUvAttempts, that.preferredPlatformUvAttempts) &&
                Objects.equals(uvModality, that.uvModality) &&
                Objects.equals(certifications, that.certifications) &&
                Objects.equals(remainingDiscoverableCredentials, that.remainingDiscoverableCredentials) &&
                Objects.equals(vendorPrototypeConfigCommands, that.vendorPrototypeConfigCommands) &&
                Objects.equals(attestationFormats, that.attestationFormats) &&
                Objects.equals(uvCountSinceLastPinEntry, that.uvCountSinceLastPinEntry) &&
                Objects.equals(longTouchForReset, that.longTouchForReset) &&
                Objects.equals(encIdentifier, that.encIdentifier) &&
                Objects.equals(transportsForReset, that.transportsForReset) &&
                Objects.equals(pinComplexityPolicy, that.pinComplexityPolicy) &&
                Objects.equals(pinComplexityPolicyURL, that.pinComplexityPolicyURL) &&
                Objects.equals(maxPINLength, that.maxPINLength) &&
                Objects.equals(encCredStoreState, that.encCredStoreState) &&
                Objects.equals(authenticatorConfigCommands, that.authenticatorConfigCommands);
    }

    @Override
    public int hashCode() {
        return Objects.hash(versions, extensions, aaguid, options, maxMsgSize, pinUvAuthProtocols,
                maxCredentialCountInList, maxCredentialIdLength, transports, algorithms,
                maxSerializedLargeBlobArray, forcePINChange, minPINLength, firmwareVersion,
                maxCredBlobLength, maxRPIDsForSetMinPINLength, preferredPlatformUvAttempts,
                uvModality, certifications, remainingDiscoverableCredentials,
                vendorPrototypeConfigCommands, attestationFormats, uvCountSinceLastPinEntry,
                longTouchForReset, encIdentifier, transportsForReset, pinComplexityPolicy,
                pinComplexityPolicyURL, maxPINLength, encCredStoreState, authenticatorConfigCommands);
    }

    /**
     * Represents the map of supported options returned by the authenticator in the authenticatorGetInfo response.
     *
     * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getinfo-options">
     * CTAP 2.3 §6.4. authenticatorGetInfo - options</a>
     */
    public static class Options {

        @JsonProperty("plat")
        @Nullable
        private final PlatformOption plat;

        @JsonProperty("rk")
        @Nullable
        private final ResidentKeyOption rk;

        @JsonProperty("clientPin")
        @Nullable
        private final ClientPINOption clientPIN;

        @JsonProperty("up")
        @Nullable
        private final UserPresenceOption up;

        @JsonProperty("uv")
        @Nullable
        private final UserVerificationOption uv;

        @JsonProperty("pinUvAuthToken")
        @JsonAlias("uvToken")
        @Nullable
        private final PinUvAuthTokenOption pinUvAuthToken;

        @JsonProperty("noMcGaPermissionsWithClientPin")
        @Nullable
        private final NoMcGaPermissionsWithClientPinOption noMcGaPermissionsWithClientPin;

        @JsonProperty("largeBlobs")
        @Nullable
        private final LargeBlobsOption largeBlobs;

        @JsonProperty("ep")
        @Nullable
        private final EnterpriseAttestationOption ep;

        @JsonProperty("bioEnroll")
        @Nullable
        private final BioEnrollOption bioEnroll;

        @JsonProperty("userVerificationMgmtPreview")
        @Nullable
        private final UserVerificationMgmtPreviewOption userVerificationMgmtPreview;

        @JsonProperty("uvBioEnroll")
        @Nullable
        private final UvBioEnrollOption uvBioEnroll;

        @JsonProperty("authnrCfg")
        @JsonAlias("config")
        @Nullable
        private final AuthnrCfgOption authnrCfg;

        @JsonProperty("uvAcfg")
        @Nullable
        private final UvAcfgOption uvAcfg;

        @JsonProperty("credMgmt")
        @Nullable
        private final CredMgmtOption credMgmt;

        @JsonProperty("perCredMgmtRO")
        @Nullable
        private final PerCredMgmtROOption perCredMgmtRO;

        @JsonProperty("credentialMgmtPreview")
        @Nullable
        private final CredentialMgmtPreviewOption credentialMgmtPreview;

        @JsonProperty("setMinPINLength")
        @Nullable
        private final SetMinPINLengthOption setMinPINLength;

        @JsonProperty("makeCredUvNotRqd")
        @Nullable
        private final MakeCredUvNotRqdOption makeCredUvNotRqd;

        @JsonProperty("alwaysUv")
        @Nullable
        private final AlwaysUvOption alwaysUv;

        @JsonCreator
        public Options(
                @JsonProperty("plat") @Nullable PlatformOption plat,
                @JsonProperty("rk") @Nullable ResidentKeyOption rk,
                @JsonProperty("clientPin") @Nullable ClientPINOption clientPIN,
                @JsonProperty("up") @Nullable UserPresenceOption up,
                @JsonProperty("uv") @Nullable UserVerificationOption uv,
                @JsonProperty("pinUvAuthToken") @JsonAlias("uvToken") @Nullable PinUvAuthTokenOption pinUvAuthToken,
                @JsonProperty("noMcGaPermissionsWithClientPin") @Nullable NoMcGaPermissionsWithClientPinOption noMcGaPermissionsWithClientPin,
                @JsonProperty("largeBlobs") @Nullable LargeBlobsOption largeBlobs,
                @JsonProperty("ep") @Nullable EnterpriseAttestationOption ep,
                @JsonProperty("bioEnroll") @Nullable BioEnrollOption bioEnroll,
                @JsonProperty("userVerificationMgmtPreview") @Nullable UserVerificationMgmtPreviewOption userVerificationMgmtPreview,
                @JsonProperty("uvBioEnroll") @Nullable UvBioEnrollOption uvBioEnroll,
                @JsonProperty("authnrCfg") @JsonAlias("config") @Nullable AuthnrCfgOption authnrCfg,
                @JsonProperty("uvAcfg") @Nullable UvAcfgOption uvAcfg,
                @JsonProperty("credMgmt") @Nullable CredMgmtOption credMgmt,
                @JsonProperty("perCredMgmtRO") @Nullable PerCredMgmtROOption perCredMgmtRO,
                @JsonProperty("credentialMgmtPreview") @Nullable CredentialMgmtPreviewOption credentialMgmtPreview,
                @JsonProperty("setMinPINLength") @Nullable SetMinPINLengthOption setMinPINLength,
                @JsonProperty("makeCredUvNotRqd") @Nullable MakeCredUvNotRqdOption makeCredUvNotRqd,
                @JsonProperty("alwaysUv") @Nullable AlwaysUvOption alwaysUv
        ) {
            this.plat = plat;
            this.rk = rk;
            this.clientPIN = clientPIN;
            this.up = up;
            this.uv = uv;
            this.pinUvAuthToken = pinUvAuthToken;
            this.noMcGaPermissionsWithClientPin = noMcGaPermissionsWithClientPin;
            this.largeBlobs = largeBlobs;
            this.ep = ep;
            this.bioEnroll = bioEnroll;
            this.userVerificationMgmtPreview = userVerificationMgmtPreview;
            this.uvBioEnroll = uvBioEnroll;
            this.authnrCfg = authnrCfg;
            this.uvAcfg = uvAcfg;
            this.credMgmt = credMgmt;
            this.perCredMgmtRO = perCredMgmtRO;
            this.credentialMgmtPreview = credentialMgmtPreview;
            this.setMinPINLength = setMinPINLength;
            this.makeCredUvNotRqd = makeCredUvNotRqd;
            this.alwaysUv = alwaysUv;
        }

        @Deprecated
        public Options(
                @Nullable PlatformOption plat,
                @Nullable ResidentKeyOption rk,
                @Nullable ClientPINOption clientPIN,
                @Nullable UserPresenceOption up,
                @Nullable UserVerificationOption uv,
                @Nullable UVTokenOption uvToken,
                @Nullable ConfigOption config
        ) {
            this(plat, rk, clientPIN, up, uv,
                    uvToken != null ? new PinUvAuthTokenOption(uvToken.getValue()) : null,
                    null, null, null, null, null, null,
                    config != null ? new AuthnrCfgOption(config.getValue()) : null,
                    null, null, null, null, null, null, null);
        }

        public @Nullable PlatformOption getPlat() {
            return plat;
        }

        public @Nullable ResidentKeyOption getRk() {
            return rk;
        }

        public @Nullable ClientPINOption getClientPIN() {
            return clientPIN;
        }

        public @Nullable UserPresenceOption getUp() {
            return up;
        }

        public @Nullable UserVerificationOption getUv() {
            return uv;
        }

        public @Nullable PinUvAuthTokenOption getPinUvAuthToken() {
            return pinUvAuthToken;
        }

        @Deprecated
        @JsonIgnore
        public @Nullable UVTokenOption getUvToken() {
            return pinUvAuthToken != null ? new UVTokenOption(pinUvAuthToken.getValue()) : null;
        }

        public @Nullable NoMcGaPermissionsWithClientPinOption getNoMcGaPermissionsWithClientPin() {
            return noMcGaPermissionsWithClientPin;
        }

        public @Nullable LargeBlobsOption getLargeBlobs() {
            return largeBlobs;
        }

        public @Nullable EnterpriseAttestationOption getEp() {
            return ep;
        }

        public @Nullable BioEnrollOption getBioEnroll() {
            return bioEnroll;
        }

        public @Nullable UserVerificationMgmtPreviewOption getUserVerificationMgmtPreview() {
            return userVerificationMgmtPreview;
        }

        public @Nullable UvBioEnrollOption getUvBioEnroll() {
            return uvBioEnroll;
        }

        public @Nullable AuthnrCfgOption getAuthnrCfg() {
            return authnrCfg;
        }

        @Deprecated
        @JsonIgnore
        public @Nullable ConfigOption getConfig() {
            return authnrCfg != null ? new ConfigOption(authnrCfg.getValue()) : null;
        }

        public @Nullable UvAcfgOption getUvAcfg() {
            return uvAcfg;
        }

        public @Nullable CredMgmtOption getCredMgmt() {
            return credMgmt;
        }

        public @Nullable PerCredMgmtROOption getPerCredMgmtRO() {
            return perCredMgmtRO;
        }

        public @Nullable CredentialMgmtPreviewOption getCredentialMgmtPreview() {
            return credentialMgmtPreview;
        }

        public @Nullable SetMinPINLengthOption getSetMinPINLength() {
            return setMinPINLength;
        }

        public @Nullable MakeCredUvNotRqdOption getMakeCredUvNotRqd() {
            return makeCredUvNotRqd;
        }

        public @Nullable AlwaysUvOption getAlwaysUv() {
            return alwaysUv;
        }

        @JsonIgnore
        public boolean isPlatform() {
            return PlatformOption.PLATFORM.equals(plat);
        }

        @JsonIgnore
        public boolean isResidentKeySupported() {
            return ResidentKeyOption.SUPPORTED.equals(rk);
        }

        @JsonIgnore
        public boolean isUserPresenceSupported() {
            return up == null || UserPresenceOption.SUPPORTED.equals(up);
        }

        @JsonIgnore
        public boolean isPinUvAuthTokenSupported() {
            return PinUvAuthTokenOption.SUPPORTED.equals(pinUvAuthToken);
        }

        @JsonIgnore
        public boolean isMcGaNotPermittedForClientPin() {
            return NoMcGaPermissionsWithClientPinOption.MC_GA_NOT_PERMITTED_FOR_CLIENT_PIN.equals(noMcGaPermissionsWithClientPin);
        }

        @JsonIgnore
        public boolean isLargeBlobsSupported() {
            return LargeBlobsOption.SUPPORTED.equals(largeBlobs);
        }

        @JsonIgnore
        public boolean isUvBioEnrollSupported() {
            return UvBioEnrollOption.SUPPORTED.equals(uvBioEnroll);
        }

        @JsonIgnore
        public boolean isAuthnrCfgSupported() {
            return AuthnrCfgOption.SUPPORTED.equals(authnrCfg);
        }

        @JsonIgnore
        public boolean isUvAcfgSupported() {
            return UvAcfgOption.SUPPORTED.equals(uvAcfg);
        }

        @JsonIgnore
        public boolean isCredMgmtSupported() {
            return CredMgmtOption.SUPPORTED.equals(credMgmt);
        }

        @JsonIgnore
        public boolean isPerCredMgmtROSupported() {
            return PerCredMgmtROOption.SUPPORTED.equals(perCredMgmtRO);
        }

        @JsonIgnore
        public boolean isCredentialMgmtPreviewSupported() {
            return CredentialMgmtPreviewOption.SUPPORTED.equals(credentialMgmtPreview);
        }

        @JsonIgnore
        public boolean isSetMinPINLengthSupported() {
            return SetMinPINLengthOption.SUPPORTED.equals(setMinPINLength);
        }

        @JsonIgnore
        public boolean isMakeCredUvNotRequired() {
            return MakeCredUvNotRqdOption.UV_NOT_REQUIRED.equals(makeCredUvNotRqd);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Options options = (Options) o;
            return Objects.equals(plat, options.plat) &&
                    Objects.equals(rk, options.rk) &&
                    Objects.equals(clientPIN, options.clientPIN) &&
                    Objects.equals(up, options.up) &&
                    Objects.equals(uv, options.uv) &&
                    Objects.equals(pinUvAuthToken, options.pinUvAuthToken) &&
                    Objects.equals(noMcGaPermissionsWithClientPin, options.noMcGaPermissionsWithClientPin) &&
                    Objects.equals(largeBlobs, options.largeBlobs) &&
                    Objects.equals(ep, options.ep) &&
                    Objects.equals(bioEnroll, options.bioEnroll) &&
                    Objects.equals(userVerificationMgmtPreview, options.userVerificationMgmtPreview) &&
                    Objects.equals(uvBioEnroll, options.uvBioEnroll) &&
                    Objects.equals(authnrCfg, options.authnrCfg) &&
                    Objects.equals(uvAcfg, options.uvAcfg) &&
                    Objects.equals(credMgmt, options.credMgmt) &&
                    Objects.equals(perCredMgmtRO, options.perCredMgmtRO) &&
                    Objects.equals(credentialMgmtPreview, options.credentialMgmtPreview) &&
                    Objects.equals(setMinPINLength, options.setMinPINLength) &&
                    Objects.equals(makeCredUvNotRqd, options.makeCredUvNotRqd) &&
                    Objects.equals(alwaysUv, options.alwaysUv);
        }

        @Override
        public int hashCode() {
            return Objects.hash(plat, rk, clientPIN, up, uv, pinUvAuthToken,
                    noMcGaPermissionsWithClientPin, largeBlobs, ep, bioEnroll,
                    userVerificationMgmtPreview, uvBioEnroll, authnrCfg, uvAcfg, credMgmt,
                    perCredMgmtRO, credentialMgmtPreview, setMinPINLength, makeCredUvNotRqd, alwaysUv);
        }

        public static class PlatformOption {

            public static final PlatformOption PLATFORM = new PlatformOption(true);
            public static final PlatformOption CROSS_PLATFORM = new PlatformOption(false);
            public static final PlatformOption NULL = null;

            private final boolean value;

            @JsonCreator
            public PlatformOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                PlatformOption that = (PlatformOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class ResidentKeyOption {

            public static final ResidentKeyOption SUPPORTED = new ResidentKeyOption(true);
            public static final ResidentKeyOption NOT_SUPPORTED = new ResidentKeyOption(false);
            public static final ResidentKeyOption NULL = null;

            private final boolean value;

            @JsonCreator
            public ResidentKeyOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                ResidentKeyOption that = (ResidentKeyOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class ClientPINOption {

            public static final ClientPINOption SET = new ClientPINOption(true);
            public static final ClientPINOption NOT_SET = new ClientPINOption(false);
            public static final ClientPINOption NOT_SUPPORTED = null;

            private final boolean value;

            @JsonCreator
            public ClientPINOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                ClientPINOption that = (ClientPINOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class UserPresenceOption {

            public static final UserPresenceOption SUPPORTED = new UserPresenceOption(true);
            public static final UserPresenceOption NOT_SUPPORTED = new UserPresenceOption(false);
            public static final UserPresenceOption NULL = null;

            private final boolean value;

            @JsonCreator
            public UserPresenceOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UserPresenceOption that = (UserPresenceOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class UserVerificationOption {

            public static final UserVerificationOption READY = new UserVerificationOption(true);
            public static final UserVerificationOption NOT_READY = new UserVerificationOption(false);
            public static final UserVerificationOption NOT_SUPPORTED = null;

            private final boolean value;

            @JsonCreator
            public UserVerificationOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UserVerificationOption that = (UserVerificationOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        @Deprecated
        public static class UVTokenOption {

            public static final UVTokenOption SUPPORTED = new UVTokenOption(true);
            public static final UVTokenOption NOT_SUPPORTED = new UVTokenOption(false);
            public static final UVTokenOption NULL = null;

            private final boolean value;

            @JsonCreator
            public UVTokenOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UVTokenOption that = (UVTokenOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        @Deprecated
        public static class ConfigOption {

            public static final ConfigOption SUPPORTED = new ConfigOption(true);
            public static final ConfigOption NOT_SUPPORTED = new ConfigOption(false);
            public static final ConfigOption NULL = null;

            private final boolean value;

            @JsonCreator
            public ConfigOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                ConfigOption that = (ConfigOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class PinUvAuthTokenOption {

            public static final PinUvAuthTokenOption SUPPORTED = new PinUvAuthTokenOption(true);
            public static final PinUvAuthTokenOption NOT_SUPPORTED = new PinUvAuthTokenOption(false);
            public static final PinUvAuthTokenOption NULL = null;

            private final boolean value;

            @JsonCreator
            public PinUvAuthTokenOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                PinUvAuthTokenOption that = (PinUvAuthTokenOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class AuthnrCfgOption {

            public static final AuthnrCfgOption SUPPORTED = new AuthnrCfgOption(true);
            public static final AuthnrCfgOption NOT_SUPPORTED = new AuthnrCfgOption(false);
            public static final AuthnrCfgOption NULL = null;

            private final boolean value;

            @JsonCreator
            public AuthnrCfgOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                AuthnrCfgOption that = (AuthnrCfgOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class NoMcGaPermissionsWithClientPinOption {

            public static final NoMcGaPermissionsWithClientPinOption MC_GA_NOT_PERMITTED_FOR_CLIENT_PIN = new NoMcGaPermissionsWithClientPinOption(true);
            public static final NoMcGaPermissionsWithClientPinOption MC_GA_PERMITTED_FOR_CLIENT_PIN = new NoMcGaPermissionsWithClientPinOption(false);
            public static final NoMcGaPermissionsWithClientPinOption NULL = null;

            private final boolean value;

            @JsonCreator
            public NoMcGaPermissionsWithClientPinOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                NoMcGaPermissionsWithClientPinOption that = (NoMcGaPermissionsWithClientPinOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class LargeBlobsOption {

            public static final LargeBlobsOption SUPPORTED = new LargeBlobsOption(true);
            public static final LargeBlobsOption NOT_SUPPORTED = new LargeBlobsOption(false);
            public static final LargeBlobsOption NULL = null;

            private final boolean value;

            @JsonCreator
            public LargeBlobsOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                LargeBlobsOption that = (LargeBlobsOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class EnterpriseAttestationOption {

            public static final EnterpriseAttestationOption ENABLED = new EnterpriseAttestationOption(true);
            public static final EnterpriseAttestationOption DISABLED = new EnterpriseAttestationOption(false);
            public static final EnterpriseAttestationOption NOT_SUPPORTED = null;

            private final boolean value;

            @JsonCreator
            public EnterpriseAttestationOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                EnterpriseAttestationOption that = (EnterpriseAttestationOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class BioEnrollOption {

            public static final BioEnrollOption PROVISIONED = new BioEnrollOption(true);
            public static final BioEnrollOption NOT_PROVISIONED = new BioEnrollOption(false);
            public static final BioEnrollOption NOT_SUPPORTED = null;

            private final boolean value;

            @JsonCreator
            public BioEnrollOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                BioEnrollOption that = (BioEnrollOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class UserVerificationMgmtPreviewOption {

            public static final UserVerificationMgmtPreviewOption PROVISIONED = new UserVerificationMgmtPreviewOption(true);
            public static final UserVerificationMgmtPreviewOption NOT_PROVISIONED = new UserVerificationMgmtPreviewOption(false);
            public static final UserVerificationMgmtPreviewOption NOT_SUPPORTED = null;

            private final boolean value;

            @JsonCreator
            public UserVerificationMgmtPreviewOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UserVerificationMgmtPreviewOption that = (UserVerificationMgmtPreviewOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class UvBioEnrollOption {

            public static final UvBioEnrollOption SUPPORTED = new UvBioEnrollOption(true);
            public static final UvBioEnrollOption NOT_SUPPORTED = new UvBioEnrollOption(false);
            public static final UvBioEnrollOption NULL = null;

            private final boolean value;

            @JsonCreator
            public UvBioEnrollOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UvBioEnrollOption that = (UvBioEnrollOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class UvAcfgOption {

            public static final UvAcfgOption SUPPORTED = new UvAcfgOption(true);
            public static final UvAcfgOption NOT_SUPPORTED = new UvAcfgOption(false);
            public static final UvAcfgOption NULL = null;

            private final boolean value;

            @JsonCreator
            public UvAcfgOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                UvAcfgOption that = (UvAcfgOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class CredMgmtOption {

            public static final CredMgmtOption SUPPORTED = new CredMgmtOption(true);
            public static final CredMgmtOption NOT_SUPPORTED = new CredMgmtOption(false);
            public static final CredMgmtOption NULL = null;

            private final boolean value;

            @JsonCreator
            public CredMgmtOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                CredMgmtOption that = (CredMgmtOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class CredentialMgmtPreviewOption {

            public static final CredentialMgmtPreviewOption SUPPORTED = new CredentialMgmtPreviewOption(true);
            public static final CredentialMgmtPreviewOption NOT_SUPPORTED = new CredentialMgmtPreviewOption(false);
            public static final CredentialMgmtPreviewOption NULL = null;

            private final boolean value;

            @JsonCreator
            public CredentialMgmtPreviewOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                CredentialMgmtPreviewOption that = (CredentialMgmtPreviewOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class SetMinPINLengthOption {

            public static final SetMinPINLengthOption SUPPORTED = new SetMinPINLengthOption(true);
            public static final SetMinPINLengthOption NOT_SUPPORTED = new SetMinPINLengthOption(false);
            public static final SetMinPINLengthOption NULL = null;

            private final boolean value;

            @JsonCreator
            public SetMinPINLengthOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                SetMinPINLengthOption that = (SetMinPINLengthOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class MakeCredUvNotRqdOption {

            public static final MakeCredUvNotRqdOption UV_NOT_REQUIRED = new MakeCredUvNotRqdOption(true);
            public static final MakeCredUvNotRqdOption UV_REQUIRED = new MakeCredUvNotRqdOption(false);
            public static final MakeCredUvNotRqdOption NULL = null;

            private final boolean value;

            @JsonCreator
            public MakeCredUvNotRqdOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                MakeCredUvNotRqdOption that = (MakeCredUvNotRqdOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class AlwaysUvOption {

            public static final AlwaysUvOption ENABLED = new AlwaysUvOption(true);
            public static final AlwaysUvOption DISABLED = new AlwaysUvOption(false);
            public static final AlwaysUvOption NOT_SUPPORTED = null;

            private final boolean value;

            @JsonCreator
            public AlwaysUvOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                AlwaysUvOption that = (AlwaysUvOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }

        public static class PerCredMgmtROOption {

            public static final PerCredMgmtROOption SUPPORTED = new PerCredMgmtROOption(true);
            public static final PerCredMgmtROOption NOT_SUPPORTED = new PerCredMgmtROOption(false);
            public static final PerCredMgmtROOption NULL = null;

            private final boolean value;

            @JsonCreator
            public PerCredMgmtROOption(boolean value) {
                this.value = value;
            }

            @JsonValue
            public boolean getValue() {
                return value;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                PerCredMgmtROOption that = (PerCredMgmtROOption) o;
                return value == that.value;
            }

            @Override
            public int hashCode() {
                return Objects.hash(value);
            }
        }
    }

}
