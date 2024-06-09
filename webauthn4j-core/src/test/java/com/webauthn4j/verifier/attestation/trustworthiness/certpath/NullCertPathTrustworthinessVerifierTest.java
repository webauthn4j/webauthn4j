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

package com.webauthn4j.verifier.attestation.trustworthiness.certpath;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.test.TestAttestationStatementUtil;
import org.junit.jupiter.api.Test;

class NullCertPathTrustworthinessVerifierTest {

    private final NullCertPathTrustworthinessVerifier validator = new NullCertPathTrustworthinessVerifier();

    @Test
    void verify() {
        PackedAttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement();
        validator.verify(new AAGUID("c4781c71-69d5-48ca-b228-c0ecaa41c75a"), attestationStatement);
    }
}