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

import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.SignatureUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

public class JWS<T> {

    private final transient Logger logger;

    private final JWSHeader header;
    private final T payload;
    private final byte[] signature;

    private final String headerString;
    private final String payloadString;

    JWS(@NonNull JWSHeader header, @NonNull String headerString, @NonNull T payload, @NonNull String payloadString, @NonNull byte[] signature) {
        logger = LoggerFactory.getLogger(JWS.class);

        this.header = header;
        this.payload = payload;
        this.signature = signature;
        this.headerString = headerString;
        this.payloadString = payloadString;
    }

    public @NonNull JWSHeader getHeader() {
        return header;
    }

    public @NonNull T getPayload() {
        return payload;
    }

    public @NonNull byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    /**
     * Validates signature.
     *
     * @return true if it pass validation
     */
    public boolean isValidSignature() {
        String signedData = headerString + "." + payloadString;
        try {
            if (header.getAlg() == null || header.getX5c() == null || header.getX5c().getCertificates().isEmpty()) {
                return false;
            }
            Signature signatureObj = SignatureUtil.createSignature(header.getAlg().getJcaName());
            PublicKey publicKey = header.getX5c().getCertificates().get(0).getPublicKey();
            signatureObj.initVerify(publicKey);
            signatureObj.update(signedData.getBytes());
            byte[] sig;
            if (publicKey instanceof ECPublicKey) {
                sig = JWSSignatureUtil.convertJwsSignatureToDerSignature(signature);
            }
            else {
                sig = signature;
            }
            return signatureObj.verify(sig);
        } catch (SignatureException | InvalidKeyException e) {
            logger.debug("Signature verification failed", e);
            return false;
        }
    }

    public @NonNull byte[] getBytes() {
        return toString().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public @NonNull String toString() {
        return headerString + "." + payloadString + "." + Base64UrlUtil.encodeToString(signature);
    }

}
