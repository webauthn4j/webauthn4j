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

package com.webauthn4j.test.authenticator.webauthn;

import com.webauthn4j.data.attestation.statement.AndroidSafetyNetAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.Response;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.test.AttestationCertificateBuilder;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.MessageDigestUtil;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.time.Instant;

public class AndroidSafetyNetAuthenticator extends WebAuthnModelAuthenticator {

    private JWSFactory jwsFactory = new JWSFactory();

    @Override
    public AttestationStatement createAttestationStatement(
            AttestationStatementRequest attestationStatementRequest,
            RegistrationEmulationOption registrationEmulationOption) {

        AttestationOption attestationOption = registrationEmulationOption.getAttestationOption() == null ? new AndroidSafetyNetAttestationOption() : registrationEmulationOption.getAttestationOption();
        X509Certificate attestationCertificate = getAttestationCertificate(attestationStatementRequest, attestationOption);
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(attestationCertificate, this.getCACertificatePath());

        JWSHeader jwsHeader = new JWSHeader(JWAIdentifier.ES256, attestationCertificatePath);
        String nonce = Base64Util.encodeToString(MessageDigestUtil.createSHA256().digest(attestationStatementRequest.getSignedData()));
        long timestampMs = Instant.now().toEpochMilli();
        String apkPackageName = "com.android.keystore.androidkeystoredemo";
        String[] apkCertificateDigestSha256 = new String[]{"bsb4/WQdaaOWYCd/j9OJiQpg7b0iwFgAc/zzA1tCfwE="};
        String apkDigestSha256 = "dM/LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2Jg=";
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;
        String advice = null;
        Response response = new Response(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, basicIntegrity, advice);

        String ver = "12685023";
        JWS<Response> jws = this.jwsFactory.create(jwsHeader, response, this.getAttestationKeyPair().getPrivate());
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            jws = this.jwsFactory.create(jws.getHeader(), jws.getPayload(), registrationEmulationOption.getSignature());
        }
        return new AndroidSafetyNetAttestationStatement(ver, jws);
    }

    @Override
    X509Certificate createAttestationCertificate(AttestationStatementRequest attestationStatementRequest, AttestationOption attestationOption) {

        AttestationCertificateBuilder builder = new AttestationCertificateBuilder(getAttestationIssuerCertificate(), new X500Principal(attestationOption.getSubjectDN()), this.getAttestationKeyPair().getPublic());

        builder.addBasicConstraintsExtension();
        builder.addKeyUsageExtension();
        return builder.build(this.getAttestationIssuerPrivateKey());
    }
}
