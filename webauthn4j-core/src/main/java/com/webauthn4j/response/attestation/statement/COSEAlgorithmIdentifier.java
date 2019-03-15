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

package com.webauthn4j.response.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.Signature;

import java.util.Arrays;

public enum COSEAlgorithmIdentifier {
    RS1(-65535, "SHA1withRSA", "SHA-1"),
    RS256(-257, "SHA256withRSA", "SHA-256"),
    RS384(-258, "SHA384withRSA", "SHA-384"),
    RS512(-259, "SHA512withRSA", "SHA-512"),
    ES256(-7, "SHA256withECDSA", "SHA-256"),
    ES384(-35, "SHA384withECDSA", "SHA-384"),
    ES512(-36, "SHA512withECDSA", "SHA-512");

    private final long value;
    private final String jcaName;
    private final String messageDigestJcaName;

    COSEAlgorithmIdentifier(long value, String jcaName, String messageDigestJcaName) {
        this.value = value;
        this.jcaName = jcaName;
        this.messageDigestJcaName = messageDigestJcaName;
    }

    public static COSEAlgorithmIdentifier create(int value) {
        return Arrays.stream(values())
                .filter(it -> it.value == (long) value)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("COSE Algorithm '" + value + "' not supported"));
    }

    @JsonCreator
    private static COSEAlgorithmIdentifier fromJson(int value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, COSEAlgorithmIdentifier.class);
        }
    }

    @JsonValue
    public long getValue() {
        return value;
    }

    public String getJcaName() {
        return jcaName;
    }

    public String getMessageDigestJcaName() {
        return messageDigestJcaName;
    }

    public Signature.SignatureVerifierBuilder signatureVerifier() {
        return Signature.SignatureVerifierBuilder.forAlgorithm(this);
    }

    public Signature.SignatureBuilder signatureBuilder() {
        return Signature.SignatureBuilder.forAlgorithm(this);
    }
}