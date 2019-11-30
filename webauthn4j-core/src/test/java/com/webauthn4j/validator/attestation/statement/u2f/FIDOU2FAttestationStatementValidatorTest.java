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

package com.webauthn4j.validator.attestation.statement.u2f;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.test.AttestationStatementProvider;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.CertificateException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FIDOU2FAttestationStatementValidatorTest {

    private FIDOU2FAttestationStatementValidator target = new FIDOU2FAttestationStatementValidator();

    @Test
    void validate_invalid_attestation_statement_test() {
        RegistrationObject registrationObject = mock(RegistrationObject.class);
        AttestationObject attestationObject = mock(AttestationObject.class);
        when(registrationObject.getAttestationObject()).thenReturn(attestationObject);
        when(attestationObject.getAttestationStatement()).thenReturn(new NoneAttestationStatement());
        assertThrows(IllegalArgumentException.class,
                () -> target.validate(registrationObject)
        );
    }

    @Test
    void validateAttestationStatement_test() {
        FIDOU2FAttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObject((AttestationStatementProvider) (collectedClientData)-> attestationStatement);
        target.validateAttestationStatement(registrationObject, attestationStatement);
    }

    @Test
    void validatePublicKey_with_rsa_key_test() {
        PublicKey publicKey = mock(PublicKey.class);
        when(publicKey.getAlgorithm()).thenReturn("RSA");
        assertThrows(CertificateException.class,
                () -> target.validatePublicKey(publicKey)
        );
    }

    @Test
    void validatePublicKey_with_non_p256_curve_ec_key_test() {
        KeyPair keyPair = ECUtil.createKeyPair(ECUtil.P_521_SPEC);
        assertThrows(CertificateException.class,
                () -> target.validatePublicKey(keyPair.getPublic())
        );
    }
}
