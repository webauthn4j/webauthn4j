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

import org.checkerframework.checker.nullness.qual.NonNull;

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
    public static @NonNull byte[] convertJwsSignatureToDerSignature(@NonNull byte[] jwsSignature) {

        // Adapted from org.apache.xml.security.algorithms.implementations.SignatureECDSA

        int rawLen = jwsSignature.length / 2;

        int i;

        for (i = rawLen; (i > 0) && (jwsSignature[rawLen - i] == 0); i--) {
            // do nothing
        }

        int j = i;

        if (jwsSignature[rawLen - i] < 0) {
            j += 1;
        }

        int k;

        for (k = rawLen; (k > 0) && (jwsSignature[2 * rawLen - k] == 0); k--) {
            // do nothing
        }

        int l = k;

        if (jwsSignature[2 * rawLen - k] < 0) {
            l += 1;
        }

        int len = 2 + j + 2 + l;

        if (len > 255) {
            throw new JWSException(INVALID_ECDSA_SIGNATURE_FORMAT);
        }

        int offset;

        final byte[] derSignature;

        if (len < 128) {
            derSignature = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        }
        else {
            derSignature = new byte[3 + 2 + j + 2 + l];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        }

        derSignature[0] = 48;
        derSignature[offset++] = (byte) len;
        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) j;

        System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

        offset += j;

        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) l;

        System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

        return derSignature;
    }

    /**
     * convert signature from DER format to JWS format
     *
     * @param derSignature signature in DER format
     * @return signature in JWS format
     */
    public static @NonNull byte[] convertDerSignatureToJwsSignature(@NonNull byte[] derSignature) {
        if (derSignature.length < 8 || derSignature[0] != 48) {
            throw new JWSException(INVALID_ECDSA_SIGNATURE_FORMAT);
        }

        int offset;
        if (derSignature[1] > 0) {
            offset = 2;
        }
        else if (derSignature[1] == (byte) 0x81) {
            offset = 3;
        }
        else {
            throw new JWSException(INVALID_ECDSA_SIGNATURE_FORMAT);
        }

        byte rLength = derSignature[offset + 1];

        int i;
        for (i = rLength; (i > 0) && (derSignature[(offset + 2 + rLength) - i] == 0); i--) {
            // do nothing
        }

        byte sLength = derSignature[offset + 2 + rLength + 1];

        int j;
        for (j = sLength; (j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--) {
            // do nothing
        }

        int rawLen = Math.max(i, j);

        if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
                || (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || derSignature[offset] != 2
                || derSignature[offset + 2 + rLength] != 2) {
            throw new JWSException(INVALID_ECDSA_SIGNATURE_FORMAT);
        }

        final byte[] concatSignature = new byte[2 * rawLen];

        System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
        System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

        return concatSignature;
    }
}
