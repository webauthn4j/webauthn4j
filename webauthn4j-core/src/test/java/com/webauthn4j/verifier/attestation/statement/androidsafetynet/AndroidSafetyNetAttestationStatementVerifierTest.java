/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.verifier.attestation.statement.androidsafetynet;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.AndroidSafetyNetAttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.Response;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.authenticator.webauthn.AndroidSafetyNetAuthenticator;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ConstantConditions")
class AndroidSafetyNetAttestationStatementVerifierTest {

    private final ClientPlatform clientPlatform = EmulatorUtil.createClientPlatform(new AndroidSafetyNetAuthenticator());
    private final AndroidSafetyNetAttestationStatementVerifier target = new AndroidSafetyNetAttestationStatementVerifier();

    @Test
    void verify_non_AndroidSafetyNetAttestation_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        assertThrows(IllegalArgumentException.class,
                () -> target.verify(registrationObject)
        );
    }

    @Test
    void verify_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity(new byte[32], "username", "displayName");

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
        PublicKeyCredentialCreationOptions credentialCreationOptions
                = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                publicKeyCredentialUserEntity,
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                Collections.emptyList(),
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.DIRECT,
                extensions
        );
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> publicKeyCredential = clientPlatform.create(credentialCreationOptions);
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObject(publicKeyCredential);
        target.verify(registrationObject);
    }

    @Test
    void verifyAttestationStatementNotNull_test() {
        String ver = "12685023";
        String nonce = "nonce";
        long timestampMs = Instant.now().toEpochMilli();
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;
        String advice = null;
        Response response = new Response(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, basicIntegrity, advice);
        JWS<Response> jws = new JWSFactory().create(new JWSHeader(JWAIdentifier.ES256, CertificateUtil.generateCertPath(Collections.emptyList())), response, new byte[32]);
        AndroidSafetyNetAttestationStatement attestationStatement = new AndroidSafetyNetAttestationStatement(ver, jws);
        target.verifyAttestationStatementNotNull(attestationStatement);
    }

    @Test
    void verifyAttestationStatementNotNull_with_null_test() {
        assertThatThrownBy(() -> target.verifyAttestationStatementNotNull(null)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyNull_with_nonce_null_test() {
        long timestampMs = Instant.now().toEpochMilli();
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;
        String advice = null;
        Response response = new Response(null, timestampMs, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, basicIntegrity, advice);
        assertThatThrownBy(() -> target.verifyResponseNotNull(response)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyNull_with_timestampMs_null_test() {
        String nonce = "nonce";
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;
        String advice = null;
        Response response = new Response(nonce, null, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, basicIntegrity, advice);
        assertThatThrownBy(() -> target.verifyResponseNotNull(response)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyNull_with_apkPackageName_null_test() {
        String nonce = "nonce";
        long timestampMs = Instant.now().toEpochMilli();
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;
        String advice = null;
        Response response = new Response(nonce, timestampMs, null, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, basicIntegrity, advice);
        assertThatThrownBy(() -> target.verifyResponseNotNull(response)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyNull_with_apkCertificateDigestSha256_null_test() {
        String nonce = "nonce";
        long timestampMs = Instant.now().toEpochMilli();
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;
        String advice = null;
        Response response = new Response(nonce, timestampMs, apkPackageName, null, apkDigestSha256, ctsProfileMatch, basicIntegrity, advice);
        assertThatThrownBy(() -> target.verifyResponseNotNull(response)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyNull_with_apkDigestSha256_null_test() {
        String nonce = "nonce";
        long timestampMs = Instant.now().toEpochMilli();
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;
        String advice = null;
        Response response = new Response(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256, null, ctsProfileMatch, basicIntegrity, advice);
        assertThatThrownBy(() -> target.verifyResponseNotNull(response)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyNull_with_ctsProfileMatch_null_test() {
        String nonce = "nonce";
        long timestampMs = Instant.now().toEpochMilli();
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean basicIntegrity = true;
        String advice = null;
        Response response = new Response(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, null, basicIntegrity, advice);
        assertThatThrownBy(() -> target.verifyResponseNotNull(response)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyNull_with_basicIntegrity_null_test() {
        String nonce = "nonce";
        long timestampMs = Instant.now().toEpochMilli();
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean ctsProfileMatch = true;
        String advice = null;
        Response response = new Response(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, null, advice);
        assertThatThrownBy(() -> target.verifyResponseNotNull(response)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyNull_with_advice_null_test() {
        String nonce = "nonce";
        long timestampMs = Instant.now().toEpochMilli();
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;
        Response response = new Response(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, basicIntegrity, null);
        assertThatCode(() -> target.verifyResponseNotNull(response)).doesNotThrowAnyException();
    }

}
