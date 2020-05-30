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

package com.webauthn4j.test;

import com.webauthn4j.data.attestation.statement.*;

public class TestAttestationStatementUtil {
    private TestAttestationStatementUtil() {
    }

    public static FIDOU2FAttestationStatement createFIDOU2FAttestationStatement() {
        return createFIDOU2FAttestationStatement(TestAttestationUtil.load2tierTestAttestationCertificatePath());
    }

    public static FIDOU2FAttestationStatement createFIDOU2FAttestationStatement(AttestationCertificatePath certPath) {

        byte[] sig = new byte[32];
        return new FIDOU2FAttestationStatement(certPath, sig);
    }

    public static PackedAttestationStatement createBasicPackedAttestationStatement() {
        byte[] signature = new byte[32]; // dummy
        return createBasicPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature);
    }

    public static PackedAttestationStatement createBasicPackedAttestationStatement(COSEAlgorithmIdentifier algorithm, byte[] signature) {
        AttestationCertificatePath certPath = TestAttestationUtil.load3tierTestAttestationCertificatePath();
        return new PackedAttestationStatement(algorithm, signature, certPath);
    }

    public static PackedAttestationStatement createSelfPackedAttestationStatement(COSEAlgorithmIdentifier algorithm, byte[] signature) {
        return new PackedAttestationStatement(algorithm, signature, null);
    }

    public static AndroidKeyAttestationStatement createAndroidKeyAttestationStatement(COSEAlgorithmIdentifier algorithm, byte[] signature) {
        AttestationCertificatePath certPath = TestAttestationUtil.load3tierTestAttestationCertificatePath();
        return new AndroidKeyAttestationStatement(algorithm, signature, certPath);
    }

}
