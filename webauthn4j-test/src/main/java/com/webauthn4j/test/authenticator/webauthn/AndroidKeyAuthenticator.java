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

import com.webauthn4j.response.attestation.statement.*;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.WIP;

import java.security.PrivateKey;

@WIP
public class AndroidKeyAuthenticator extends WebAuthnModelAuthenticator{

    private PrivateKey attestationPrivateKey;
    private AttestationCertificatePath attestationCertificatePath;

    public AndroidKeyAuthenticator(PrivateKey attestationPrivateKey, AttestationCertificatePath attestationCertificatePath){
        super();
        this.attestationPrivateKey = attestationPrivateKey;
        this.attestationCertificatePath = attestationCertificatePath;
    }

    @Override
    protected AttestationStatement generateAttestationStatement(byte[] signedData, RegistrationEmulationOption registrationEmulationOption) {
        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(attestationPrivateKey, signedData);
        }
        return new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, attestationCertificatePath);
    }

}
