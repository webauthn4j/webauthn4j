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

package com.webauthn4j;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class WebAuthnRegistrationManagerTest {

    @Test
    void constructor_test() {
        NoneAttestationStatementVerifier noneAttestationStatementValidator = new NoneAttestationStatementVerifier();
        PackedAttestationStatementVerifier packedAttestationStatementValidator = new PackedAttestationStatementVerifier();
        FIDOU2FAttestationStatementVerifier fidoU2FAttestationStatementValidator = new FIDOU2FAttestationStatementVerifier();
        AndroidKeyAttestationStatementVerifier androidKeyAttestationStatementValidator = new AndroidKeyAttestationStatementVerifier();
        TrustAnchorRepository trustAnchorRepository = TestAttestationUtil.createTrustAnchorRepositoryWith3tierTestRootCACertificate();
        WebAuthnRegistrationManager webAuthnRegistrationManager = new WebAuthnRegistrationManager(
                Arrays.asList(
                        noneAttestationStatementValidator,
                        packedAttestationStatementValidator,
                        fidoU2FAttestationStatementValidator,
                        androidKeyAttestationStatementValidator),
                new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository),
                new DefaultSelfAttestationTrustworthinessVerifier()
        );
        assertThat(webAuthnRegistrationManager).isNotNull();
    }

    @Test
    void createNonStrictWebAuthnRegistrationManager_test() {
        assertThat(WebAuthnRegistrationManager.createNonStrictWebAuthnRegistrationManager()).isNotNull();
    }


}