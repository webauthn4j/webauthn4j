/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.verifier.attestation.trustworthiness.self;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.SelfAttestationProhibitedException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultSelfAttestationTrustworthinessVerifierTest {

    @Test
    void verify_test() {
        DefaultSelfAttestationTrustworthinessVerifier validator = new DefaultSelfAttestationTrustworthinessVerifier();
        PackedAttestationStatement attestationStatement = TestAttestationStatementUtil.createSelfPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32]);

        validator.verify(attestationStatement);
    }

    @Test
    void verify_basic_type_attestation_statement_test() {
        DefaultSelfAttestationTrustworthinessVerifier validator = new DefaultSelfAttestationTrustworthinessVerifier();
        PackedAttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement();

        assertThrows(BadAttestationStatementException.class,
                () -> validator.verify(attestationStatement)
        );
    }

    @Test
    void verify_test_with_self_attestation_allowed_false() {
        DefaultSelfAttestationTrustworthinessVerifier validator = new DefaultSelfAttestationTrustworthinessVerifier(false);
        PackedAttestationStatement attestationStatement = TestAttestationStatementUtil.createSelfPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32]);

        assertThrows(SelfAttestationProhibitedException.class,
                () -> validator.verify(attestationStatement)
        );
    }
}