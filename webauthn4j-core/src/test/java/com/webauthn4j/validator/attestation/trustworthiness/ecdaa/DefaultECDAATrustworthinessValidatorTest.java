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

package com.webauthn4j.validator.attestation.trustworthiness.ecdaa;

import com.webauthn4j.response.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

public class DefaultECDAATrustworthinessValidatorTest {

    @Test(expected = NotImplementedException.class)
    public void validate_test() {
        DefaultECDAATrustworthinessValidator validator = new DefaultECDAATrustworthinessValidator();
        PackedAttestationStatement attestationStatement = mock(PackedAttestationStatement.class);

        validator.validate(attestationStatement);
    }
}