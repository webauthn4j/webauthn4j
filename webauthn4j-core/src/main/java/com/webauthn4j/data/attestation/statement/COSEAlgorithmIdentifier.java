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

package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class COSEAlgorithmIdentifier implements Serializable {

    public static final COSEAlgorithmIdentifier RS1 = new COSEAlgorithmIdentifier(-65535, "SHA1withRSA", "SHA-1");
    public static final COSEAlgorithmIdentifier RS256 = new COSEAlgorithmIdentifier(-257, "SHA256withRSA", "SHA-256");
    public static final COSEAlgorithmIdentifier RS384 = new COSEAlgorithmIdentifier(-258, "SHA384withRSA", "SHA-384");
    public static final COSEAlgorithmIdentifier RS512 = new COSEAlgorithmIdentifier(-259, "SHA512withRSA", "SHA-512");
    public static final COSEAlgorithmIdentifier ES256 = new COSEAlgorithmIdentifier(-7, "SHA256withECDSA", "SHA-256");
    public static final COSEAlgorithmIdentifier ES384 = new COSEAlgorithmIdentifier(-35, "SHA384withECDSA", "SHA-384");
    public static final COSEAlgorithmIdentifier ES512 = new COSEAlgorithmIdentifier(-36, "SHA512withECDSA", "SHA-512");
    public static final COSEAlgorithmIdentifier PS256 = new COSEAlgorithmIdentifier(-37, "SHA256withRSA/PSS", "SHA-256");
    public static final COSEAlgorithmIdentifier PS384 = new COSEAlgorithmIdentifier(-38, "SHA384withRSA/PSS", "SHA-384");
    public static final COSEAlgorithmIdentifier PS512 = new COSEAlgorithmIdentifier(-39, "SHA512withRSA/PSS", "SHA-512");

    private static final Map<Long, COSEAlgorithmIdentifier> predefinedAlgorithmMap = new HashMap<>();

    static {
        predefinedAlgorithmMap.put(RS1.value, RS1);
        predefinedAlgorithmMap.put(RS256.value, RS256);
        predefinedAlgorithmMap.put(RS384.value, RS384);
        predefinedAlgorithmMap.put(RS512.value, RS512);
        predefinedAlgorithmMap.put(ES256.value, ES256);
        predefinedAlgorithmMap.put(ES384.value, ES384);
        predefinedAlgorithmMap.put(ES512.value, ES512);
        predefinedAlgorithmMap.put(PS256.value, PS256);
        predefinedAlgorithmMap.put(PS384.value, PS384);
        predefinedAlgorithmMap.put(PS512.value, PS512);
    }

    private final long value;
    private final String jcaName;
    private final String messageDigestJcaName;

    private COSEAlgorithmIdentifier(long value, String jcaName, String messageDigestJcaName) {
        this.value = value;
        this.jcaName = jcaName;
        this.messageDigestJcaName = messageDigestJcaName;
    }

    // COSEAlgorithmIdentifier doesn't accept jcaName and messageDigestJcaName from caller for the time being
    public static COSEAlgorithmIdentifier create(long value) {

        COSEAlgorithmIdentifier identifier = predefinedAlgorithmMap.get(value);
        if(identifier == null){
            identifier = new COSEAlgorithmIdentifier(value, null, null);
        }
        return identifier;
    }

    @JsonCreator
    private static COSEAlgorithmIdentifier deserialize(long value) throws InvalidFormatException {
        return create(value);
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        COSEAlgorithmIdentifier that = (COSEAlgorithmIdentifier) o;
        return value == that.value &&
                Objects.equals(jcaName, that.jcaName) &&
                Objects.equals(messageDigestJcaName, that.messageDigestJcaName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value, jcaName, messageDigestJcaName);
    }
}
