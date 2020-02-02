/*
 * Copyright 2018 the original author or authors.
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

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.SignatureUtil;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

public class JWSFactory {

    private JsonConverter jsonConverter;

    public JWSFactory(ObjectConverter objectConverter) {
        this.jsonConverter = objectConverter.getJsonConverter();
    }

    public JWSFactory() {
        this(new ObjectConverter());
    }

    public <T extends Serializable> JWS<T> create(JWSHeader header, T payload, PrivateKey privateKey) {
        String headerString = Base64UrlUtil.encodeToString(jsonConverter.writeValueAsString(header).getBytes(StandardCharsets.UTF_8));
        String payloadString = Base64UrlUtil.encodeToString(jsonConverter.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8));
        String signedData = headerString + "." + payloadString;
        Signature signatureObj = SignatureUtil.createSignature(header.getAlg().getJcaName());
        try {
            signatureObj.initSign(privateKey);
            signatureObj.update(signedData.getBytes());
            byte[] derSignature = signatureObj.sign();
            byte[] jwsSignature = JWSSignatureUtil.convertDerSignatureToJwsSignature(derSignature);
            return new JWS<>(header, headerString, payload, payloadString, jwsSignature);
        } catch (InvalidKeyException | SignatureException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public <T extends Serializable> JWS<T> create(JWSHeader header, T payload, byte[] signature) {
        String headerString = Base64UrlUtil.encodeToString(jsonConverter.writeValueAsString(header).getBytes(StandardCharsets.UTF_8));
        String payloadString = Base64UrlUtil.encodeToString(jsonConverter.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8));
        return new JWS<>(header, headerString, payload, payloadString, signature);
    }

    public <T extends Serializable> JWS<T> parse(String value, Class<T> payloadType) {
        String[] data = value.split("\\.");
        if (data.length != 3) {
            throw new IllegalArgumentException("JWS value is not divided by two period.");
        }
        String headerString = data[0];
        String payloadString = data[1];
        String signatureString = data[2];
        JWSHeader header = jsonConverter.readValue(new String(Base64UrlUtil.decode(headerString)), JWSHeader.class);
        T payload = jsonConverter.readValue(new String(Base64UrlUtil.decode(payloadString)), payloadType);
        byte[] signature = Base64UrlUtil.decode(signatureString);
        return new JWS<>(header, headerString, payload, payloadString, signature);
    }

}
