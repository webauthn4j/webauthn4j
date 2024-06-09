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

package com.webauthn4j.verifier;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.verifier.attestation.statement.androidkey.NullAndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.NullPackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.NullTPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CoreRegistrationDataVerifierTest {
    final ObjectConverter objectConverter = new ObjectConverter();
    final CoreRegistrationDataVerifier target = new CoreRegistrationDataVerifier(Arrays.asList(
            new NoneAttestationStatementVerifier(),
            new NullFIDOU2FAttestationStatementVerifier(),
            new NullPackedAttestationStatementVerifier(),
            new NullTPMAttestationStatementVerifier(),
            new NullAndroidKeyAttestationStatementVerifier(),
            new NullAndroidSafetyNetAttestationStatementVerifier()
    ),
            new NullCertPathTrustworthinessVerifier(),
            new NullSelfAttestationTrustworthinessVerifier(),
            Collections.emptyList(),
            objectConverter);

    @Test
    void verifyCOSEKey_test() {
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
        assertThatThrownBy(() -> target.verifyCOSEKey(ec2COSEKey)).isInstanceOf(ConstraintViolationException.class);
    }

}