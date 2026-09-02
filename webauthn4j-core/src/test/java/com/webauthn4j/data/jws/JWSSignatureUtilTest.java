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

package com.webauthn4j.data.jws;

import com.webauthn4j.data.internal.asn1.der.ASN1Integer;
import com.webauthn4j.data.internal.asn1.der.ASN1Sequence;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for the DER to JWS signature conversion.
 * <p>
 * RFC 7518 Section 3.4 requires the JWS signature to be R || S with each component
 * at the fixed length of the curve (32 bytes for ES256, 48 for ES384, 66 for ES512),
 * regardless of how many significant bytes r and s happen to have. A conversion that
 * sizes the output from the larger of the two components emits a short signature
 * whenever both r and s are numerically small, which strict verifiers reject.
 * For ES512 this occurs for roughly a quarter of all signatures, because the P-521
 * group order leaves the top byte of the 66-byte representation almost empty.
 */
class JWSSignatureUtilTest {

    private static byte[] derSignature(BigInteger r, BigInteger s) {
        ASN1Integer rInteger = ASN1Integer.create(r.toByteArray());
        ASN1Integer sInteger = ASN1Integer.create(s.toByteArray());
        return ASN1Sequence.create(rInteger, sInteger).toBytes();
    }

    /** A positive value whose magnitude occupies exactly {@code length} bytes with the top bit clear. */
    private static BigInteger positiveOfLength(int length) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) 0x7F);
        return new BigInteger(1, bytes);
    }

    @Test
    void convertDerSignatureToJwsSignature_es256_short_components_test() {
        BigInteger r = positiveOfLength(31);
        BigInteger s = positiveOfLength(31);
        byte[] jws = JWSSignatureUtil.convertDerSignatureToJwsSignature(derSignature(r, s), JWAIdentifier.ES256);
        assertThat(jws).hasSize(64);
        assertThat(jws[0]).isEqualTo((byte) 0x00);
        assertThat(jws[32]).isEqualTo((byte) 0x00);
    }

    @Test
    void convertDerSignatureToJwsSignature_es384_short_components_test() {
        BigInteger r = positiveOfLength(47);
        BigInteger s = positiveOfLength(47);
        byte[] jws = JWSSignatureUtil.convertDerSignatureToJwsSignature(derSignature(r, s), JWAIdentifier.ES384);
        assertThat(jws).hasSize(96);
        assertThat(jws[0]).isEqualTo((byte) 0x00);
        assertThat(jws[48]).isEqualTo((byte) 0x00);
    }

    @Test
    void convertDerSignatureToJwsSignature_es512_short_components_test() {
        // For P-521 both components fit in 65 bytes about a quarter of the time,
        // so this is the case a length-from-max conversion gets wrong most often.
        BigInteger r = positiveOfLength(65);
        BigInteger s = positiveOfLength(65);
        byte[] jws = JWSSignatureUtil.convertDerSignatureToJwsSignature(derSignature(r, s), JWAIdentifier.ES512);
        assertThat(jws).hasSize(132);
        assertThat(jws[0]).isEqualTo((byte) 0x00);
        assertThat(jws[66]).isEqualTo((byte) 0x00);
    }

    @Test
    void convertDerSignatureToJwsSignature_full_length_components_test() {
        assertThat(JWSSignatureUtil.convertDerSignatureToJwsSignature(
                derSignature(positiveOfLength(32), positiveOfLength(32)), JWAIdentifier.ES256)).hasSize(64);
        assertThat(JWSSignatureUtil.convertDerSignatureToJwsSignature(
                derSignature(positiveOfLength(48), positiveOfLength(48)), JWAIdentifier.ES384)).hasSize(96);
        assertThat(JWSSignatureUtil.convertDerSignatureToJwsSignature(
                derSignature(positiveOfLength(66), positiveOfLength(66)), JWAIdentifier.ES512)).hasSize(132);
    }

    @Test
    void convertDerSignatureToJwsSignature_round_trip_test() {
        BigInteger r = positiveOfLength(31);
        BigInteger s = positiveOfLength(30);
        byte[] jws = JWSSignatureUtil.convertDerSignatureToJwsSignature(derSignature(r, s), JWAIdentifier.ES256);
        byte[] der = JWSSignatureUtil.convertJwsSignatureToDerSignature(jws);
        assertThat(der).isEqualTo(derSignature(r, s));
    }

    @Test
    void convertDerSignatureToJwsSignature_non_ecdsa_alg_test() {
        byte[] der = derSignature(positiveOfLength(31), positiveOfLength(31));
        assertThatThrownBy(() -> JWSSignatureUtil.convertDerSignatureToJwsSignature(der, JWAIdentifier.RS256))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
