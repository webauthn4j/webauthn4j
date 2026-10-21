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

package com.webauthn4j.appattest;

import com.webauthn4j.anchor.KeyStoreTrustAnchorRepository;
import com.webauthn4j.appattest.data.extension.AppleBundleVersion01ExtensionAuthenticatorOutput;
import com.webauthn4j.appattest.data.extension.AppleValidationCategory01ExtensionAuthenticatorOutput;
import com.webauthn4j.appattest.data.*;
import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.HexUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.verifier.exception.BadSignatureException;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.BufferUnderflowException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mockStatic;

class DeviceCheckManagerIOS27Test {

    private static final String APP_IDENTIFIER = "K38V9TR83U.com.example.webauthn4j.appattest.debug";
    private static final String IOS27_EXTENSIONS = "A2776170706C655F62756E646C655F76657273696F6E5F30316131781C6170706C655F76616C69646174696F6E5F63617465676F72795F30314403000000";

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    void apple_extensions_cbor_round_trip_test() {
        ObjectConverter converter = DeviceCheckManager.createObjectConverter();
        ValidationCategory validationCategory = ValidationCategory.DEVELOPMENT;
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> extensions =
                TestDataUtil.createAppAttestAuthenticatorExtensions("1", validationCategory);

        byte[] serialized = converter.getCborMapper().writeValueAsBytes(extensions);
        assertThat(serialized).isEqualTo(HexUtil.decode(IOS27_EXTENSIONS));

        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> deserialized =
                converter.getCborMapper().readValue(serialized,
                        new TypeReference<AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput>>() {});

        assertThat(deserialized.getKeys()).containsExactlyInAnyOrder(
                AppleBundleVersion01ExtensionAuthenticatorOutput.ID,
                AppleValidationCategory01ExtensionAuthenticatorOutput.ID);
        assertThat(deserialized.getExtension(AppleBundleVersion01ExtensionAuthenticatorOutput.class).getBundleVersion())
                .isEqualTo("1");
        assertThat(deserialized.getExtension(AppleValidationCategory01ExtensionAuthenticatorOutput.class).getValidationCategory())
                .isEqualTo(validationCategory);
        assertThat(converter.getCborMapper().writeValueAsBytes(deserialized)).isEqualTo(serialized);
    }

    @Test
    void validate_ios27_attestation_test() throws GeneralSecurityException, IOException {
        byte[] keyId = Base64UrlUtil.decode("5wvMiiwopebQYSxU76gBmh-9evrXbDwi2hdEIr8FXzM");
        byte[] attestationObject = Base64UrlUtil.decode(loadResource("apple-app-attest/ios27-sample-attestation-object.b64url").trim());
        byte[] clientDataHash = HexUtil.decode("5b1e4a7f3c2d8e91a605b3d472f8196ce347aa582c9d310e8467b2531fc09e77");

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("apple-app-attest", TestAttestationUtil.loadCertificateFromClassPath(
                "apple-app-attest/Apple_App_Attestation_Root_CA.pem"));
        DeviceCheckManager manager = new DeviceCheckManager(
                new DefaultCertPathTrustworthinessVerifier(new KeyStoreTrustAnchorRepository(trustStore)));

        // Keep verification within the sample credential certificate's validity period.
        Instant timestamp = Instant.parse("2026-10-20T00:00:00Z");
        DCAttestationData dcAttestationData;
        try (MockedStatic<Instant> mocked = mockStatic(Instant.class)) {
            mocked.when(Instant::now).thenReturn(timestamp);
            dcAttestationData = manager.validate(new DCAttestationRequest(keyId, attestationObject, clientDataHash),
                    new DCAttestationParameters(new DCServerProperty(APP_IDENTIFIER, new DefaultChallenge(clientDataHash))));
        }

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = dcAttestationData.getAttestationObject().getAuthenticatorData();
        assertThat(AuthenticatorData.checkFlagAT(authenticatorData.getFlags())).isTrue();
        assertThat(AuthenticatorData.checkFlagED(authenticatorData.getFlags())).isTrue();
        assertThat(authenticatorData.getAttestedCredentialData().getCredentialId()).isEqualTo(keyId);
        assertThat(authenticatorData.getExtensions().getKeys()).containsExactlyInAnyOrder("apple_bundle_version_01", "apple_validation_category_01");
        assertThat(authenticatorData.getExtensions().getExtension(AppleBundleVersion01ExtensionAuthenticatorOutput.class).getBundleVersion()).isEqualTo("1");
        assertThat(authenticatorData.getExtensions().getExtension(AppleValidationCategory01ExtensionAuthenticatorOutput.class).getValidationCategory()).isEqualTo(ValidationCategory.DEVELOPMENT);
    }

    @Test
    void validate_ios27_assertion_with_extensions_test() {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = MessageDigestUtil.createSHA256().digest("key".getBytes(StandardCharsets.UTF_8));
        byte[] challenge = "assertion_challenge".getBytes(StandardCharsets.UTF_8);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);
        byte[] authenticatorData = TestDataUtil.createAppAttestAssertionAuthenticatorData(APP_IDENTIFIER, 1, HexUtil.decode(IOS27_EXTENSIONS));
        byte[] assertion = TestDataUtil.createAppAttestAssertion(keyPair, authenticatorData, clientDataHash);

        DCAssertionData dcAssertionData = DeviceCheckManager.createNonStrictDeviceCheckManager().validate(
                new DCAssertionRequest(keyId, assertion, clientDataHash),
                new DCAssertionParameters(new DCServerProperty(APP_IDENTIFIER, new DefaultChallenge(challenge)), TestDataUtil.createAppAttestDevice(keyPair, keyId))
        );

        assertThat(dcAssertionData.getAuthenticatorDataBytes()).isEqualTo(authenticatorData);
        assertThat(dcAssertionData.getAuthenticatorData().getAttestedCredentialData()).isNull();
        assertThat(dcAssertionData.getAuthenticatorData().getSignCount()).isEqualTo(1);
        assertThat(dcAssertionData.getAuthenticatorData().getExtensions().getKeys()).containsExactlyInAnyOrder("apple_bundle_version_01", "apple_validation_category_01");
        assertThat(dcAssertionData.getAuthenticatorData().getExtensions().getExtension(AppleBundleVersion01ExtensionAuthenticatorOutput.class).getBundleVersion()).isEqualTo("1");
        assertThat(dcAssertionData.getAuthenticatorData().getExtensions().getExtension(AppleValidationCategory01ExtensionAuthenticatorOutput.class).getValidationCategory()).isEqualTo(ValidationCategory.DEVELOPMENT);
    }

    @Test
    void validate_ios27_assertion_with_tampered_extensions_test() {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = MessageDigestUtil.createSHA256().digest("key".getBytes(StandardCharsets.UTF_8));
        byte[] challenge = "assertion_challenge".getBytes(StandardCharsets.UTF_8);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);
        byte[] signedAuthenticatorData = TestDataUtil.createAppAttestAssertionAuthenticatorData(APP_IDENTIFIER, 1, HexUtil.decode(IOS27_EXTENSIONS));
        byte[] tamperedAuthenticatorData = signedAuthenticatorData.clone();
        tamperedAuthenticatorData[tamperedAuthenticatorData.length - 4] = 0x02;
        byte[] assertion = TestDataUtil.createAppAttestAssertion(keyPair, signedAuthenticatorData, clientDataHash, tamperedAuthenticatorData);

        DeviceCheckManager deviceCheckManager = DeviceCheckManager.createNonStrictDeviceCheckManager();
        DCAssertionRequest dcAssertionRequest = new DCAssertionRequest(keyId, assertion, clientDataHash);
        DCAssertionParameters dcAssertionParameters = new DCAssertionParameters(new DCServerProperty(APP_IDENTIFIER, new DefaultChallenge(challenge)), TestDataUtil.createAppAttestDevice(keyPair, keyId));

        assertThatThrownBy(() -> deviceCheckManager.validate(dcAssertionRequest, dcAssertionParameters))
                .isInstanceOf(BadSignatureException.class);
    }

    @Test
    void parse_attestation_with_extensions_instead_of_credential_data_test() {
        byte[] attestationObject = Base64UrlUtil.decode(loadResource("apple-app-attest/ios27-sample-attestation-object.b64url").trim());
        ObjectNode node = (ObjectNode) objectConverter.getCborMapper().readTree(attestationObject);
        // AT is set, but the bytes contain only extensions, as in an assertion.
        node.put("authData", TestDataUtil.createAppAttestAssertionAuthenticatorData(APP_IDENTIFIER, 0, HexUtil.decode(IOS27_EXTENSIONS)));
        byte[] malformedAttestationObject = objectConverter.getCborMapper().writeValueAsBytes(node);
        DCAttestationRequest request = new DCAttestationRequest(new byte[32], malformedAttestationObject, new byte[32]);
        DeviceCheckManager manager = DeviceCheckManager.createNonStrictDeviceCheckManager();

        assertThatThrownBy(() -> manager.parse(request))
                .hasRootCauseInstanceOf(BufferUnderflowException.class);
    }

    private String loadResource(String path) {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path)) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
