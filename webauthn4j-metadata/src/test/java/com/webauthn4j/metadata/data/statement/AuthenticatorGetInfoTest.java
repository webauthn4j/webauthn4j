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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PinProtocolVersion;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticatorGetInfoTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper().rebuild()
            .addModule(new WebAuthnMetadataJSONModule())
            .build();

    // ==================== AuthenticatorGetInfo top-level ====================

    @Test
    void authenticatorGetInfo_deserialization_test() {
        AuthenticatorGetInfo info = jsonMapper.readValue(AUTHENTICATOR_GET_INFO_JSON, AuthenticatorGetInfo.class);
        assertThat(info.getVersions()).containsExactly("U2F_V2", "FIDO_2_0");
        assertThat(info.getExtensions()).containsExactly("credProtect", "hmac-secret");
        assertThat(info.getAaguid()).isEqualTo(new AAGUID("0132d110-bf4e-4208-a403-ab4f5f12efe5"));
        assertThat(info.getOptions()).isNotNull();
        assertThat(info.getMaxMsgSize()).isEqualTo(1200);
        assertThat(info.getPinUvAuthProtocols()).containsExactly(PinProtocolVersion.VERSION_1);
        assertThat(info.getMaxCredentialCountInList()).isEqualTo(16);
        assertThat(info.getMaxCredentialIdLength()).isEqualTo(128);
        assertThat(info.getTransports()).containsExactly(AuthenticatorTransport.USB, AuthenticatorTransport.NFC);
        assertThat(info.getAlgorithms()).hasSize(2);
        assertThat(info.getFirmwareVersion()).isEqualTo(5);
        assertThat(info.getMaxSerializedLargeBlobArray()).isEqualTo(4096);
        assertThat(info.getForcePINChange()).isFalse();
        assertThat(info.getMinPINLength()).isEqualTo(4);
        assertThat(info.getMaxCredBlobLength()).isEqualTo(32);
        assertThat(info.getMaxRPIDsForSetMinPINLength()).isEqualTo(3);
        assertThat(info.getPreferredPlatformUvAttempts()).isEqualTo(5);
        assertThat(info.getUvModality()).containsExactly(UserVerificationMethod.FINGERPRINT_INTERNAL);
        assertThat(info.getCertifications()).containsKey("FIDO");
        assertThat(info.getRemainingDiscoverableCredentials()).isEqualTo(25);
        assertThat(info.getVendorPrototypeConfigCommands()).containsExactly(1, 2);
        assertThat(info.getAttestationFormats()).containsExactly("packed", "fido-u2f");
        assertThat(info.getUvCountSinceLastPinEntry()).isEqualTo(3);
        assertThat(info.getLongTouchForReset()).isTrue();
        assertThat(info.getEncIdentifier()).isEqualTo("abc123");
        assertThat(info.getTransportsForReset()).containsExactly(AuthenticatorTransport.USB);
        assertThat(info.getPinComplexityPolicy()).isTrue();
        assertThat(info.getPinComplexityPolicyURL()).isEqualTo("https://example.com/policy");
        assertThat(info.getMaxPINLength()).isEqualTo(64);
        assertThat(info.getEncCredStoreState()).isEqualTo("state123");
        assertThat(info.getAuthenticatorConfigCommands()).containsExactly(3, 4);
    }

    @Test
    void authenticatorGetInfo_aaguid_serialization_test() {
        AuthenticatorGetInfo info = new AuthenticatorGetInfo(
                java.util.List.of("FIDO_2_0"), null,
                new AAGUID("33c1642b-b5e9-423d-9add-5a0119c2a8b8"),
                null, null, null);
        String json = jsonMapper.writeValueAsString(info);
        assertThat(json).contains("\"aaguid\":\"33c1642b-b5e9-423d-9add-5a0119c2a8b8\"");
    }

    // ==================== Options deserialization ====================

    @Test
    void options_deserialization_test() {
        AuthenticatorGetInfo.Options options = jsonMapper.readValue(ALL_OPTIONS_JSON, AuthenticatorGetInfo.Options.class);

        assertThat(options.getPlat()).isEqualTo(AuthenticatorGetInfo.Options.PlatformOption.CROSS_PLATFORM);
        assertThat(options.getRk()).isEqualTo(AuthenticatorGetInfo.Options.ResidentKeyOption.SUPPORTED);
        assertThat(options.getClientPIN()).isEqualTo(AuthenticatorGetInfo.Options.ClientPINOption.SET);
        assertThat(options.getUp()).isEqualTo(AuthenticatorGetInfo.Options.UserPresenceOption.SUPPORTED);
        assertThat(options.getUv()).isEqualTo(AuthenticatorGetInfo.Options.UserVerificationOption.READY);
        assertThat(options.getPinUvAuthToken()).isEqualTo(AuthenticatorGetInfo.Options.PinUvAuthTokenOption.SUPPORTED);
        assertThat(options.getNoMcGaPermissionsWithClientPin()).isEqualTo(AuthenticatorGetInfo.Options.NoMcGaPermissionsWithClientPinOption.MC_GA_NOT_PERMITTED_FOR_CLIENT_PIN);
        assertThat(options.getLargeBlobs()).isEqualTo(AuthenticatorGetInfo.Options.LargeBlobsOption.SUPPORTED);
        assertThat(options.getEp()).isEqualTo(AuthenticatorGetInfo.Options.EnterpriseAttestationOption.ENABLED);
        assertThat(options.getBioEnroll()).isEqualTo(AuthenticatorGetInfo.Options.BioEnrollOption.PROVISIONED);
        assertThat(options.getUserVerificationMgmtPreview()).isEqualTo(AuthenticatorGetInfo.Options.UserVerificationMgmtPreviewOption.PROVISIONED);
        assertThat(options.getUvBioEnroll()).isEqualTo(AuthenticatorGetInfo.Options.UvBioEnrollOption.SUPPORTED);
        assertThat(options.getAuthnrCfg()).isEqualTo(AuthenticatorGetInfo.Options.AuthnrCfgOption.SUPPORTED);
        assertThat(options.getUvAcfg()).isEqualTo(AuthenticatorGetInfo.Options.UvAcfgOption.SUPPORTED);
        assertThat(options.getCredMgmt()).isEqualTo(AuthenticatorGetInfo.Options.CredMgmtOption.SUPPORTED);
        assertThat(options.getPerCredMgmtRO()).isEqualTo(AuthenticatorGetInfo.Options.PerCredMgmtROOption.SUPPORTED);
        assertThat(options.getCredentialMgmtPreview()).isEqualTo(AuthenticatorGetInfo.Options.CredentialMgmtPreviewOption.SUPPORTED);
        assertThat(options.getSetMinPINLength()).isEqualTo(AuthenticatorGetInfo.Options.SetMinPINLengthOption.SUPPORTED);
        assertThat(options.getMakeCredUvNotRqd()).isEqualTo(AuthenticatorGetInfo.Options.MakeCredUvNotRqdOption.UV_NOT_REQUIRED);
        assertThat(options.getAlwaysUv()).isEqualTo(AuthenticatorGetInfo.Options.AlwaysUvOption.ENABLED);
    }

    @Test
    void options_old_format_deserialization_test() {
        String json = "{\"uvToken\": true, \"config\": false}";
        AuthenticatorGetInfo.Options options = jsonMapper.readValue(json, AuthenticatorGetInfo.Options.class);
        assertThat(options.getPinUvAuthToken()).isEqualTo(AuthenticatorGetInfo.Options.PinUvAuthTokenOption.SUPPORTED);
        assertThat(options.getAuthnrCfg()).isEqualTo(AuthenticatorGetInfo.Options.AuthnrCfgOption.NOT_SUPPORTED);
    }

    // ==================== Options serialization ====================

    @Test
    void options_serialization_test() {
        AuthenticatorGetInfo.Options options = jsonMapper.readValue(ALL_OPTIONS_JSON, AuthenticatorGetInfo.Options.class);
        String json = jsonMapper.writeValueAsString(options);

        assertThat(json).contains("\"plat\":false");
        assertThat(json).contains("\"rk\":true");
        assertThat(json).contains("\"clientPin\":true");
        assertThat(json).contains("\"up\":true");
        assertThat(json).contains("\"uv\":true");
        assertThat(json).contains("\"pinUvAuthToken\":true");
        assertThat(json).contains("\"noMcGaPermissionsWithClientPin\":true");
        assertThat(json).contains("\"largeBlobs\":true");
        assertThat(json).contains("\"ep\":true");
        assertThat(json).contains("\"bioEnroll\":true");
        assertThat(json).contains("\"userVerificationMgmtPreview\":true");
        assertThat(json).contains("\"uvBioEnroll\":true");
        assertThat(json).contains("\"authnrCfg\":true");
        assertThat(json).contains("\"uvAcfg\":true");
        assertThat(json).contains("\"credMgmt\":true");
        assertThat(json).contains("\"perCredMgmtRO\":true");
        assertThat(json).contains("\"credentialMgmtPreview\":true");
        assertThat(json).contains("\"setMinPINLength\":true");
        assertThat(json).contains("\"makeCredUvNotRqd\":true");
        assertThat(json).contains("\"alwaysUv\":true");
        assertThat(json).doesNotContain("\"value\"");
        assertThat(json).doesNotContain("\"uvToken\"");
        assertThat(json).doesNotContain("\"config\"");
    }

    // ==================== Options round-trip ====================

    @Test
    void options_roundTrip_test() {
        AuthenticatorGetInfo.Options deserialized = jsonMapper.readValue(ALL_OPTIONS_JSON, AuthenticatorGetInfo.Options.class);
        String reserialized = jsonMapper.writeValueAsString(deserialized);
        AuthenticatorGetInfo.Options roundTripped = jsonMapper.readValue(reserialized, AuthenticatorGetInfo.Options.class);
        assertThat(roundTripped).isEqualTo(deserialized);
    }

    @Test
    void options_oldFormat_roundTrip_test() {
        String oldJson = "{\"plat\": false, \"rk\": true, \"uvToken\": true, \"config\": false}";
        AuthenticatorGetInfo.Options deserialized = jsonMapper.readValue(oldJson, AuthenticatorGetInfo.Options.class);
        String reserialized = jsonMapper.writeValueAsString(deserialized);
        assertThat(reserialized).contains("\"pinUvAuthToken\":true");
        assertThat(reserialized).contains("\"authnrCfg\":false");
        assertThat(reserialized).doesNotContain("\"uvToken\"");
        assertThat(reserialized).doesNotContain("\"config\"");

        AuthenticatorGetInfo.Options roundTripped = jsonMapper.readValue(reserialized, AuthenticatorGetInfo.Options.class);
        assertThat(roundTripped).isEqualTo(deserialized);
    }

    // ==================== Options helper methods ====================

    @Test
    void options_helper_methods_test() {
        AuthenticatorGetInfo.Options options = jsonMapper.readValue(ALL_OPTIONS_JSON, AuthenticatorGetInfo.Options.class);

        assertThat(options.isPlatform()).isFalse();
        assertThat(options.isResidentKeySupported()).isTrue();
        assertThat(options.isUserPresenceSupported()).isTrue();
        assertThat(options.isPinUvAuthTokenSupported()).isTrue();
        assertThat(options.isMcGaNotPermittedForClientPin()).isTrue();
        assertThat(options.isLargeBlobsSupported()).isTrue();
        assertThat(options.isUvBioEnrollSupported()).isTrue();
        assertThat(options.isAuthnrCfgSupported()).isTrue();
        assertThat(options.isUvAcfgSupported()).isTrue();
        assertThat(options.isCredMgmtSupported()).isTrue();
        assertThat(options.isPerCredMgmtROSupported()).isTrue();
        assertThat(options.isCredentialMgmtPreviewSupported()).isTrue();
        assertThat(options.isSetMinPINLengthSupported()).isTrue();
        assertThat(options.isMakeCredUvNotRequired()).isTrue();
    }

    @Test
    void options_helper_methods_with_absent_test() {
        AuthenticatorGetInfo.Options options = jsonMapper.readValue("{}", AuthenticatorGetInfo.Options.class);

        assertThat(options.isPlatform()).isFalse();
        assertThat(options.isResidentKeySupported()).isFalse();
        assertThat(options.isUserPresenceSupported()).isTrue();
        assertThat(options.isPinUvAuthTokenSupported()).isFalse();
        assertThat(options.isMcGaNotPermittedForClientPin()).isFalse();
        assertThat(options.isLargeBlobsSupported()).isFalse();
        assertThat(options.isUvBioEnrollSupported()).isFalse();
        assertThat(options.isAuthnrCfgSupported()).isFalse();
        assertThat(options.isUvAcfgSupported()).isFalse();
        assertThat(options.isCredMgmtSupported()).isFalse();
        assertThat(options.isPerCredMgmtROSupported()).isFalse();
        assertThat(options.isCredentialMgmtPreviewSupported()).isFalse();
        assertThat(options.isSetMinPINLengthSupported()).isFalse();
        assertThat(options.isMakeCredUvNotRequired()).isFalse();
    }

    // ==================== Options deprecated compatibility ====================

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_constructor_test() {
        AuthenticatorGetInfo.Options options = new AuthenticatorGetInfo.Options(
                AuthenticatorGetInfo.Options.PlatformOption.CROSS_PLATFORM,
                AuthenticatorGetInfo.Options.ResidentKeyOption.SUPPORTED,
                AuthenticatorGetInfo.Options.ClientPINOption.SET,
                AuthenticatorGetInfo.Options.UserPresenceOption.SUPPORTED,
                AuthenticatorGetInfo.Options.UserVerificationOption.READY,
                AuthenticatorGetInfo.Options.UVTokenOption.SUPPORTED,
                AuthenticatorGetInfo.Options.ConfigOption.SUPPORTED
        );
        assertThat(options.getPlat()).isEqualTo(AuthenticatorGetInfo.Options.PlatformOption.CROSS_PLATFORM);
        assertThat(options.getPinUvAuthToken()).isEqualTo(AuthenticatorGetInfo.Options.PinUvAuthTokenOption.SUPPORTED);
        assertThat(options.getAuthnrCfg()).isEqualTo(AuthenticatorGetInfo.Options.AuthnrCfgOption.SUPPORTED);
        assertThat(options.getLargeBlobs()).isNull();
    }

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_getUvToken_test() {
        String json = "{\"pinUvAuthToken\": false}";
        AuthenticatorGetInfo.Options options = jsonMapper.readValue(json, AuthenticatorGetInfo.Options.class);
        assertThat(options.getUvToken()).isNotNull();
        assertThat(options.getUvToken().getValue()).isEqualTo(options.getPinUvAuthToken().getValue());
        assertThat(options.getUvToken()).isInstanceOf(AuthenticatorGetInfo.Options.UVTokenOption.class);
    }

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_getUvToken_returns_null_when_absent_test() {
        AuthenticatorGetInfo.Options options = jsonMapper.readValue("{}", AuthenticatorGetInfo.Options.class);
        assertThat(options.getUvToken()).isNull();
    }

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_getConfig_test() {
        String json = "{\"authnrCfg\": true}";
        AuthenticatorGetInfo.Options options = jsonMapper.readValue(json, AuthenticatorGetInfo.Options.class);
        assertThat(options.getConfig()).isNotNull();
        assertThat(options.getConfig().getValue()).isEqualTo(options.getAuthnrCfg().getValue());
        assertThat(options.getConfig()).isInstanceOf(AuthenticatorGetInfo.Options.ConfigOption.class);
    }

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_getConfig_returns_null_when_absent_test() {
        AuthenticatorGetInfo.Options options = jsonMapper.readValue("{}", AuthenticatorGetInfo.Options.class);
        assertThat(options.getConfig()).isNull();
    }

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_UVTokenOption_equals_and_hashCode_test() {
        AuthenticatorGetInfo.Options.UVTokenOption a = new AuthenticatorGetInfo.Options.UVTokenOption(true);
        AuthenticatorGetInfo.Options.UVTokenOption b = new AuthenticatorGetInfo.Options.UVTokenOption(true);
        AuthenticatorGetInfo.Options.UVTokenOption c = new AuthenticatorGetInfo.Options.UVTokenOption(false);
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
        assertThat(a).isNotEqualTo(c);
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("string");
    }

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_ConfigOption_equals_and_hashCode_test() {
        AuthenticatorGetInfo.Options.ConfigOption a = new AuthenticatorGetInfo.Options.ConfigOption(true);
        AuthenticatorGetInfo.Options.ConfigOption b = new AuthenticatorGetInfo.Options.ConfigOption(true);
        AuthenticatorGetInfo.Options.ConfigOption c = new AuthenticatorGetInfo.Options.ConfigOption(false);
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
        assertThat(a).isNotEqualTo(c);
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("string");
    }

    // ==================== Options equals / hashCode ====================

    @Test
    void options_equals_and_hashCode_test() {
        AuthenticatorGetInfo.Options a = jsonMapper.readValue(ALL_OPTIONS_JSON, AuthenticatorGetInfo.Options.class);
        AuthenticatorGetInfo.Options b = jsonMapper.readValue(ALL_OPTIONS_JSON, AuthenticatorGetInfo.Options.class);
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
        assertThat(a).isEqualTo(a);
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("string");

        AuthenticatorGetInfo.Options empty = jsonMapper.readValue("{}", AuthenticatorGetInfo.Options.class);
        assertThat(a).isNotEqualTo(empty);
    }

    @Test
    void option_type_equals_and_hashCode_test() {
        AuthenticatorGetInfo.Options.PinUvAuthTokenOption a = new AuthenticatorGetInfo.Options.PinUvAuthTokenOption(true);
        AuthenticatorGetInfo.Options.PinUvAuthTokenOption b = new AuthenticatorGetInfo.Options.PinUvAuthTokenOption(true);
        AuthenticatorGetInfo.Options.PinUvAuthTokenOption c = new AuthenticatorGetInfo.Options.PinUvAuthTokenOption(false);
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
        assertThat(a).isNotEqualTo(c);
        assertThat(a).isNotEqualTo(null);
        assertThat(a).isNotEqualTo("string");
    }

    // ==================== Test data ====================

    private static final String ALL_OPTIONS_JSON = """
            {
                "plat": false,
                "rk": true,
                "clientPin": true,
                "up": true,
                "uv": true,
                "pinUvAuthToken": true,
                "noMcGaPermissionsWithClientPin": true,
                "largeBlobs": true,
                "ep": true,
                "bioEnroll": true,
                "userVerificationMgmtPreview": true,
                "uvBioEnroll": true,
                "authnrCfg": true,
                "uvAcfg": true,
                "credMgmt": true,
                "perCredMgmtRO": true,
                "credentialMgmtPreview": true,
                "setMinPINLength": true,
                "makeCredUvNotRqd": true,
                "alwaysUv": true
            }
            """;

    private static final String AUTHENTICATOR_GET_INFO_JSON = """
            {
                "versions": ["U2F_V2", "FIDO_2_0"],
                "extensions": ["credProtect", "hmac-secret"],
                "aaguid": "0132d110bf4e4208a403ab4f5f12efe5",
                "options": {
                    "plat": false,
                    "rk": true,
                    "clientPin": true,
                    "up": true,
                    "uv": true,
                    "uvToken": false,
                    "config": false
                },
                "maxMsgSize": 1200,
                "pinUvAuthProtocols": [1],
                "maxCredentialCountInList": 16,
                "maxCredentialIdLength": 128,
                "transports": ["usb", "nfc"],
                "algorithms": [
                    {"type": "public-key", "alg": -7},
                    {"type": "public-key", "alg": -257}
                ],
                "maxSerializedLargeBlobArray": 4096,
                "forcePINChange": false,
                "minPINLength": 4,
                "firmwareVersion": 5,
                "maxCredBlobLength": 32,
                "maxRPIDsForSetMinPINLength": 3,
                "preferredPlatformUvAttempts": 5,
                "uvModality": 2,
                "certifications": {"FIDO": 1},
                "remainingDiscoverableCredentials": 25,
                "vendorPrototypeConfigCommands": [1, 2],
                "attestationFormats": ["packed", "fido-u2f"],
                "uvCountSinceLastPinEntry": 3,
                "longTouchForReset": true,
                "encIdentifier": "abc123",
                "transportsForReset": ["usb"],
                "pinComplexityPolicy": true,
                "pinComplexityPolicyURL": "https://example.com/policy",
                "maxPINLength": 64,
                "encCredStoreState": "state123",
                "authenticatorConfigCommands": [3, 4]
            }
            """;
}
