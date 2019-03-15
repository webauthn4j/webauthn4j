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

package com.webauthn4j.util.jws;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.Signature.SignatureVerifierBuilder;
import com.webauthn4j.validator.exception.BadSignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

public class JWS<T extends Serializable> implements Serializable {

    transient Logger logger = LoggerFactory.getLogger(JWS.class);

    private JWSHeader header;

    private T payload;

    private byte[] signature;

    private String headerString;
    private String payloadString;

    private JWS(JWSHeader header, String headerString, T payload, String payloadString, byte[] signature) {
        this.header = header;
        this.payload = payload;
        this.signature = signature;
        this.headerString = headerString;
        this.payloadString = payloadString;
    }

    public static <T extends Serializable> JWS<T> parse(String value, JsonConverter jsonConverter, Class<T> type) {
        String[] data = value.split("\\.");
        if (data.length != 3) {
            throw new IllegalArgumentException("JWS value is not divided by two period.");
        }
        String headerString = data[0];
        String payloadString = data[1];
        String signatureString = data[2];
        JWSHeader header = jsonConverter.readValue(new String(Base64UrlUtil.decode(headerString)), JWSHeader.class);
        T payload = jsonConverter.readValue(new String(Base64UrlUtil.decode(payloadString)), type);
        byte[] signature = Base64UrlUtil.decode(signatureString);
        return new JWS<>(header, headerString, payload, payloadString, signature);
    }

    public JWSHeader getHeader() {
        return header;
    }

    public String getHeaderString() {
        return headerString;
    }

    public T getPayload() {
        return payload;
    }

    public String getPayloadString() {
        return payloadString;
    }

    public byte[] getSignature() {
        return signature;
    }

    public boolean isValidSignature() {
        String signedData = headerString + "." + payloadString;
        try {
            PublicKey publicKey = header.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();

            SignatureVerifierBuilder signatureVerifierBuilder = header.getAlg().signatureVerifier()
                    .publicKey(publicKey)
                    .update(signedData.getBytes());

            byte[] sig;
            if (publicKey instanceof ECPublicKey) {
                sig = JWSSignatureUtil.convertJWSSignatureToDerSignature(signature);
            } else {
                sig = signature;
            }
            return signatureVerifierBuilder.verify(sig);
        } catch (BadSignatureException e) {
            logger.debug("Signature verification failed", e);
            return false;
        }
    }


}
