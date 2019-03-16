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

package com.webauthn4j.data.jws;

class JWSSignatureUtil {

    private JWSSignatureUtil(){}

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
     * @param jwsSignature signature in JWS format
     * @return signature in DER format
     * @author Vladimir Dzhuvinov
     * @author Aleksei Doroganov
     */
    public static byte[] convertJWSSignatureToDerSignature(byte[] jwsSignature) {

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
            throw new JWSException("Invalid ECDSA signature format");
        }

        int offset;

        final byte[] derSignature;

        if (len < 128) {
            derSignature = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        } else {
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
}
