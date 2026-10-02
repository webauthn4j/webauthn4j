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

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.appattest.authenticator.DCAppleDeviceImpl;
import com.webauthn4j.appattest.data.*;
import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.HexUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.BadSignatureException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;

class DeviceCheckManagerIOS27Test {

    private static final String APP_IDENTIFIER = "1234567890.com.example.myapp";
    private static final String IOS27_EXTENSIONS = "A2776170706C655F62756E646C655F76657273696F6E5F30316131781C6170706C655F76616C69646174696F6E5F63617465676F72795F30314401000000";

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    void validate_ios27_attestation_from_apple_validation_guide_test() {
        byte[] keyId = Base64Util.decode("zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=");
        byte[] attestationObject = Base64Util.decode(loadResource("apple-app-attest/ios27-sample-attestation-object.b64").trim());
        byte[] challenge = "example_server_challenge".getBytes(StandardCharsets.UTF_8);

        DeviceCheckManager deviceCheckManager = new DeviceCheckManager(new DefaultCertPathTrustworthinessVerifier(appleAppAttestTrustAnchorRepository()));
        DCAttestationRequest dcAttestationRequest = new DCAttestationRequest(keyId, attestationObject, challenge);
        DCAttestationParameters dcAttestationParameters = new DCAttestationParameters(new DCServerProperty(APP_IDENTIFIER, new DefaultChallenge(challenge)));

        Instant timestamp = Instant.parse("2026-04-21T00:00:00Z");
        DCAttestationData dcAttestationData;
        try (MockedStatic<Instant> mocked = mockStatic(Instant.class)) {
            mocked.when(Instant::now).thenReturn(timestamp);
            dcAttestationData = deviceCheckManager.validate(dcAttestationRequest, dcAttestationParameters);
        }

        AuthenticatorData<?> authenticatorData = dcAttestationData.getAttestationObject().getAuthenticatorData();
        assertThat(AuthenticatorData.checkFlagED(authenticatorData.getFlags())).isFalse();
        assertThat(authenticatorData.getAttestedCredentialData().getCredentialId()).isEqualTo(keyId);
        assertThat(authenticatorData.getExtensions().getKeys()).containsExactlyInAnyOrder("apple_bundle_version_01", "apple_validation_category_01");
    }

    @Test
    void validate_ios27_assertion_with_unflagged_extensions_test() throws GeneralSecurityException {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = MessageDigestUtil.createSHA256().digest("key".getBytes(StandardCharsets.UTF_8));
        byte[] challenge = "assertion_challenge".getBytes(StandardCharsets.UTF_8);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);
        byte[] authenticatorData = ios27AssertionAuthenticatorData(1);
        byte[] assertion = assertion(keyPair, authenticatorData, clientDataHash);

        DCAssertionData dcAssertionData = DeviceCheckManager.createNonStrictDeviceCheckManager().validate(
                new DCAssertionRequest(keyId, assertion, clientDataHash),
                new DCAssertionParameters(new DCServerProperty(APP_IDENTIFIER, new DefaultChallenge(challenge)), appleDevice(keyPair, keyId))
        );

        assertThat(dcAssertionData.getAuthenticatorDataBytes()).isEqualTo(authenticatorData);
        assertThat(dcAssertionData.getAuthenticatorData().getAttestedCredentialData()).isNull();
        assertThat(dcAssertionData.getAuthenticatorData().getSignCount()).isEqualTo(1);
        assertThat(dcAssertionData.getAuthenticatorData().getExtensions().getKeys()).containsExactlyInAnyOrder("apple_bundle_version_01", "apple_validation_category_01");
    }

    @Test
    void validate_ios27_assertion_with_tampered_extensions_test() throws GeneralSecurityException {
        KeyPair keyPair = ECUtil.createKeyPair();
        byte[] keyId = MessageDigestUtil.createSHA256().digest("key".getBytes(StandardCharsets.UTF_8));
        byte[] challenge = "assertion_challenge".getBytes(StandardCharsets.UTF_8);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);
        byte[] signedAuthenticatorData = ios27AssertionAuthenticatorData(1);
        byte[] tamperedAuthenticatorData = signedAuthenticatorData.clone();
        tamperedAuthenticatorData[tamperedAuthenticatorData.length - 4] = 0x02;
        byte[] assertion = assertion(keyPair, signedAuthenticatorData, clientDataHash, tamperedAuthenticatorData);

        DeviceCheckManager deviceCheckManager = DeviceCheckManager.createNonStrictDeviceCheckManager();
        DCAssertionRequest dcAssertionRequest = new DCAssertionRequest(keyId, assertion, clientDataHash);
        DCAssertionParameters dcAssertionParameters = new DCAssertionParameters(new DCServerProperty(APP_IDENTIFIER, new DefaultChallenge(challenge)), appleDevice(keyPair, keyId));

        assertThrows(BadSignatureException.class, () -> deviceCheckManager.validate(dcAssertionRequest, dcAssertionParameters));
    }

    private byte[] ios27AssertionAuthenticatorData(long counter) {
        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(APP_IDENTIFIER.getBytes(StandardCharsets.UTF_8));
        byte[] extensions = HexUtil.decode(IOS27_EXTENSIONS);
        return ByteBuffer.allocate(rpIdHash.length + 1 + 4 + extensions.length)
                .put(rpIdHash)
                .put(AuthenticatorData.BIT_AT)
                .putInt((int) counter)
                .put(extensions)
                .array();
    }

    private byte[] assertion(KeyPair keyPair, byte[] authenticatorData, byte[] clientDataHash) throws GeneralSecurityException {
        return assertion(keyPair, authenticatorData, clientDataHash, authenticatorData);
    }

    private byte[] assertion(KeyPair keyPair, byte[] signedAuthenticatorData, byte[] clientDataHash, byte[] sentAuthenticatorData) throws GeneralSecurityException {
        byte[] nonce = MessageDigestUtil.createSHA256().digest(
                ByteBuffer.allocate(signedAuthenticatorData.length + clientDataHash.length).put(signedAuthenticatorData).put(clientDataHash).array()
        );
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(nonce);
        Map<String, byte[]> assertion = new LinkedHashMap<>();
        assertion.put("signature", signature.sign());
        assertion.put("authenticatorData", sentAuthenticatorData);
        return objectConverter.getCborMapper().writeValueAsBytes(assertion);
    }

    private DCAppleDevice appleDevice(KeyPair keyPair, byte[] keyId) {
        AttestedCredentialData attestedCredentialData = new AttestedCredentialData(
                new AAGUID("appattest\0\0\0\0\0\0\0".getBytes(StandardCharsets.UTF_8)),
                keyId,
                EC2COSEKey.create((ECPublicKey) keyPair.getPublic(), COSEAlgorithmIdentifier.ES256)
        );
        return new DCAppleDeviceImpl(attestedCredentialData, null, 0, new AuthenticationExtensionsAuthenticatorOutputs<>());
    }

    private TrustAnchorRepository appleAppAttestTrustAnchorRepository() {
        Set<TrustAnchor> trustAnchors = Collections.singleton(new TrustAnchor(loadCertificate("apple-app-attest/Apple_App_Attestation_Root_CA.pem"), null));
        return new TrustAnchorRepository() {
            @Override
            public Set<TrustAnchor> find(AAGUID aaguid) {
                return trustAnchors;
            }

            @Override
            public Set<TrustAnchor> find(byte[] attestationCertificateKeyIdentifier) {
                return trustAnchors;
            }
        };
    }

    private X509Certificate loadCertificate(String path) {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path)) {
            return CertificateUtil.generateX509Certificate(inputStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private String loadResource(String path) {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path)) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, read);
            }
            return new String(outputStream.toByteArray(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
