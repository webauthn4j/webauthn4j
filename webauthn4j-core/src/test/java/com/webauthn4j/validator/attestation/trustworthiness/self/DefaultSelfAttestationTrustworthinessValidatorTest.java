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

package com.webauthn4j.validator.attestation.trustworthiness.self;

import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.response.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.SelfAttestationProhibitedException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultSelfAttestationTrustworthinessValidatorTest {

    @Test
    void validate_test() {
        DefaultSelfAttestationTrustworthinessValidator validator = new DefaultSelfAttestationTrustworthinessValidator();
        PackedAttestationStatement attestationStatement = TestAttestationUtil.createSelfPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32]);

        validator.validate(attestationStatement);
    }

    @Test
    void validate_basic_type_attestation_statement_test() {
        DefaultSelfAttestationTrustworthinessValidator validator = new DefaultSelfAttestationTrustworthinessValidator();
        PackedAttestationStatement attestationStatement = TestAttestationUtil.createBasicPackedAttestationStatement();

        assertThrows(BadAttestationStatementException.class,
                () -> validator.validate(attestationStatement)
        );
    }

    @Test
    void validate_test_with_self_attestation_allowed_false() {
        DefaultSelfAttestationTrustworthinessValidator validator = new DefaultSelfAttestationTrustworthinessValidator();
        validator.setSelfAttestationAllowed(false);
        PackedAttestationStatement attestationStatement = TestAttestationUtil.createSelfPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32]);

        assertThrows(SelfAttestationProhibitedException.class,
                () -> validator.validate(attestationStatement)
        );
    }
}