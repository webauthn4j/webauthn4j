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

package com.webauthn4j.validator;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.validator.attestation.statement.androidkey.NullAndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.NullPackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.NullTPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.NullFIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CoreRegistrationDataValidatorTest {
    final ObjectConverter objectConverter = new ObjectConverter();
    final CoreRegistrationDataValidator target = new CoreRegistrationDataValidator(Arrays.asList(
            new NoneAttestationStatementValidator(),
            new NullFIDOU2FAttestationStatementValidator(),
            new NullPackedAttestationStatementValidator(),
            new NullTPMAttestationStatementValidator(),
            new NullAndroidKeyAttestationStatementValidator(),
            new NullAndroidSafetyNetAttestationStatementValidator()
    ),
            new NullCertPathTrustworthinessValidator(),
            new NullSelfAttestationTrustworthinessValidator(),
            Collections.emptyList(),
            objectConverter);

    @Test
    void validateCOSEKey_test() {
        EC2COSEKey original = EC2COSEKey.create((ECPrivateKey) ECUtil.createKeyPair().getPrivate());
        EC2COSEKey ec2COSEKey = new EC2COSEKey(
                original.getKeyId(),
                COSEAlgorithmIdentifier.ES256,
                original.getKeyOps(),
                original.getCurve(),
                null,
                null,
                original.getD()
        );
        assertThatThrownBy(() -> target.validateCOSEKey(ec2COSEKey)).isInstanceOf(ConstraintViolationException.class);
    }

}