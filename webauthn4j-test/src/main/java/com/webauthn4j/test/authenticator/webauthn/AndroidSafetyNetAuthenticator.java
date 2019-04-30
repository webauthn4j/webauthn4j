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
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.WIP;

import java.security.PrivateKey;

@WIP
public class AndroidSafetyNetAuthenticator extends WebAuthnModelAuthenticator {

    private PrivateKey attestationPrivateKey;
    private AttestationCertificatePath attestationCertificatePath;


    @Override
    protected AttestationStatement generateAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption) {
        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(attestationPrivateKey, attestationStatementRequest.getSignedData());
        }
        JWSHeader jwsHeader = new JWSHeader(JWAIdentifier.ES256, attestationCertificatePath);
        String nonce = null; //TODO
        long timestampMs = 0;  //TODO
        String apkPackageName = null;  //TODO
        String[] apkCertificateDigestSha256 = null;  //TODO
        String apkDigestSha256 = null;  //TODO
        boolean ctsProfileMatch = true;
        boolean basicIntegrity = true;  //TODO
        String advice = null;  //TODO
        Response response = new Response(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256,apkDigestSha256, ctsProfileMatch, basicIntegrity, advice);

        String ver = ""; //TODO
        JWS<Response> responseJWS = new JWS<>(jwsHeader, null, response, null, signature);
        return new AndroidSafetyNetAttestationStatement(ver, responseJWS);
    }
}
