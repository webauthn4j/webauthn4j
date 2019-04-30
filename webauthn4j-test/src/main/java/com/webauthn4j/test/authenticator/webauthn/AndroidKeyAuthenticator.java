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

import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.RegistrationEmulationOption;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class AndroidKeyAuthenticator extends WebAuthnModelAuthenticator{

    private PrivateKey issuerPrivateKey;
    private AttestationCertificatePath caCertificates;

    public AndroidKeyAuthenticator(PrivateKey issuerPrivateKey, AttestationCertificatePath caCertificates){
        super();
        this.issuerPrivateKey = issuerPrivateKey;
        this.caCertificates = caCertificates;
    }

    public AndroidKeyAuthenticator(){
        this(
                TestAttestationUtil.load3tierTestIntermediateCAPrivateKey(),
                TestAttestationUtil.load3tierTestCACertPath());
    }

    @Override
    protected AttestationStatement generateAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption) {
        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(attestationStatementRequest.getCredentialKeyPair().getPrivate(), attestationStatementRequest.getSignedData());
        }
        X509Certificate issuerCertificate = caCertificates.get(0);
        X509Certificate attestationCertificate =
                TestAttestationUtil.createAndroidKeyAttestationCertificate(
                        issuerCertificate,
                        issuerPrivateKey,
                        attestationStatementRequest.getCredentialKeyPair().getPublic(),
                        attestationStatementRequest.getClientDataHash());
        List<X509Certificate> list = new ArrayList<>();
        list.add(attestationCertificate);
        list.addAll(caCertificates);
        AttestationCertificatePath attestationCertificates = new AttestationCertificatePath(list);
        return new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, attestationCertificates);
    }

}
