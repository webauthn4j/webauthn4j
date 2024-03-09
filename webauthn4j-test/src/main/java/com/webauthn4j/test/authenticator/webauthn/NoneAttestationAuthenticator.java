/*
 * Copyright 2023 the original author or authors.
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

package com.webauthn4j.test.authenticator.webauthn;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.test.client.RegistrationEmulationOption;

import java.security.cert.X509Certificate;

// None attesation format authenticator
// as described in https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
public class NoneAttestationAuthenticator extends WebAuthnModelAuthenticator {

    public NoneAttestationAuthenticator(
            AAGUID aaguid,
            int counter,
            boolean capableOfUserVerification,
            ObjectConverter objectConverter) {
        super(aaguid, null, null, null, counter, capableOfUserVerification, objectConverter);
    }

    public NoneAttestationAuthenticator() {
        this(
            AAGUID.ZERO,
            0,
            true,
            new ObjectConverter()
        );
    }

    @Override
    public AttestationStatement createAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption) {
        return new NoneAttestationStatement();
    }

    @Override
    protected X509Certificate createAttestationCertificate(AttestationStatementRequest attestationStatementRequest, AttestationOption attestationOption) {
        return null;
    }
}
