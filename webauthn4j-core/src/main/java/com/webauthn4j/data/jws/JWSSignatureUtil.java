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
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.util.Arrays;

class JWSSignatureUtil {

    private static final String INVALID_ECDSA_SIGNATURE_FORMAT = "Invalid ECDSA signature format";

    private JWSSignatureUtil() {
    }

    /*
     * Original License Header
     */

    /*
     * nimbus-jose-jwt
     *
     * Copyright 2012-2016, Connect2id Ltd.
     *
     * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
     * this file except in compliance with the License. You may obtain a copy of the
     * License at
     *
     *    http://www.apache.org/licenses/LICENSE-2.0
     *
     * Unless required by applicable law or agreed to in writing, software distributed
     * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
     * CONDITIONS OF ANY KIND, either express or implied. See the License for the
     * specific language governing permissions and limitations under the License.
     */

    // Adapted from com.nimbusds.jose.crypto.ECDSAVerifier
    // Original site: https://bitbucket.org/connect2id/nimbus-jose-jwt/src/a97f123a1ad29906befcb94f9c86a98d47c37fd4/src/main/java/com/nimbusds/jose/crypto/impl/ECDSA.java?at=master&fileviewer=file-view-default

    /**
     * convert signature from JWS format to DER format
     *
     * @param jwsSignature signature in JWS format
     * @return signature in DER format
     * @author Vladimir Dzhuvinov
     * @author Aleksei Doroganov
     */
    public static @NotNull byte[] convertJwsSignatureToDerSignature(@NotNull byte[] jwsSignature) {

        AssertUtil.notNull(jwsSignature, "jwsSignature must not be null");

        int rawLen = jwsSignature.length / 2;

        byte[] rBytes = Arrays.copyOfRange(jwsSignature, 0, rawLen);
        byte[] sBytes = Arrays.copyOfRange(jwsSignature, rawLen, jwsSignature.length);

        // BigInteger handles leading zero stripping and sign-extension
        byte[] r = new BigInteger(1, rBytes).toByteArray();
        byte[] s = new BigInteger(1, sBytes).toByteArray();

        ASN1Integer rInt = ASN1Integer.create(r);
        ASN1Integer sInt = ASN1Integer.create(s);
        return ASN1Sequence.create(rInt, sInt).toBytes();
    }

    /**
     * convert signature from DER format to JWS format
     *
     * @param derSignature signature in DER format
     * @return signature in JWS format
     */
    public static @NotNull byte[] convertDerSignatureToJwsSignature(@NotNull byte[] derSignature) {
        ASN1Sequence seq;
        try {
            seq = ASN1Sequence.parse(derSignature);
        }
        catch (Exception e) {
            throw new JWSException(INVALID_ECDSA_SIGNATURE_FORMAT, e);
        }

        if (seq.size() != 2) {
            throw new JWSException(INVALID_ECDSA_SIGNATURE_FORMAT);
        }

        BigInteger r = ((ASN1Integer) seq.get(0)).getContent();
        BigInteger s = ((ASN1Integer) seq.get(1)).getContent();

        // Determine raw component length from the larger of the two
        byte[] rUnsigned = toUnsignedByteArray(r);
        byte[] sUnsigned = toUnsignedByteArray(s);
        int rawLen = Math.max(rUnsigned.length, sUnsigned.length);

        // Pad to fixed-length and concatenate
        byte[] concatSignature = new byte[2 * rawLen];
        System.arraycopy(rUnsigned, 0, concatSignature, rawLen - rUnsigned.length, rUnsigned.length);
        System.arraycopy(sUnsigned, 0, concatSignature, 2 * rawLen - sUnsigned.length, sUnsigned.length);

        return concatSignature;
    }

    private static byte[] toUnsignedByteArray(BigInteger value) {
        byte[] bytes = value.toByteArray();
        // Remove leading zero byte if present (sign-extension)
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
