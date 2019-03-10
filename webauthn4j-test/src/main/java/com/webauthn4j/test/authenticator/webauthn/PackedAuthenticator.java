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

import com.webauthn4j.response.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.response.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.test.TestDataConstants;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.RegistrationEmulationOption;

import java.security.PrivateKey;

public class PackedAuthenticator extends WebAuthnModelAuthenticator {

    private PrivateKey attestationPrivateKey;
    private AttestationCertificatePath attestationCertificatePath;

    public PackedAuthenticator(){
        super();
        this.attestationPrivateKey = TestDataConstants.GENERIC_3TIER_ATTESTATION_PRIVATE_KEY;
        this.attestationCertificatePath = TestDataConstants.GENERIC_3TIER_ATTESTATION_CERTIFICATE_PATH;
    }

    @Override
    public AttestationStatement generateAttestationStatement(byte[] signedData, RegistrationEmulationOption registrationEmulationOption){
        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(attestationPrivateKey, signedData);
        }
        return new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, attestationCertificatePath, null);
    }
}
