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

import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.RegistrationEmulationOption;

import java.security.cert.X509Certificate;

public class PackedAuthenticator extends WebAuthnModelAuthenticator {

    @Override
    public AttestationStatement createAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption, AttestationOption attestationOption){
        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(this.getAttestationKeyPair().getPrivate(), attestationStatementRequest.getSignedData());
        }

        attestationOption = attestationOption == null ? new PackedAttestationOption() : attestationOption;
        X509Certificate attestationCertificate = getAttestationCertificate(attestationStatementRequest, attestationOption);
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(attestationCertificate, this.getCACertificatePath());
        return new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, attestationCertificatePath, null);
    }

    @Override
    protected X509Certificate createAttestationCertificate(AttestationStatementRequest attestationStatementRequest, AttestationOption attestationOption){
        return TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate(); //TODO
    }
}
