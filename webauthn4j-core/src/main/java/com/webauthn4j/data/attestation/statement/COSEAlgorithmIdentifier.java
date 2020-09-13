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

package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class COSEAlgorithmIdentifier implements Serializable {

    public static final COSEAlgorithmIdentifier RS1;
    public static final COSEAlgorithmIdentifier RS256;
    public static final COSEAlgorithmIdentifier RS384;
    public static final COSEAlgorithmIdentifier RS512;
    public static final COSEAlgorithmIdentifier ES256;
    public static final COSEAlgorithmIdentifier ES384;
    public static final COSEAlgorithmIdentifier ES512;

    private static Map<COSEAlgorithmIdentifier, COSEKeyType> keyTypeMap = new HashMap<>();
    private static Map<COSEAlgorithmIdentifier, String> algorithmMap = new HashMap<>();
    private static Map<COSEAlgorithmIdentifier, String> messageDigestAlgorithmMap = new HashMap<>();

    static {
        RS1 = new COSEAlgorithmIdentifier(-65535);
        RS256 = new COSEAlgorithmIdentifier(-257);
        RS384 = new COSEAlgorithmIdentifier(-258);
        RS512 = new COSEAlgorithmIdentifier(-259);
        ES256 = new COSEAlgorithmIdentifier(-7);
        ES384 = new COSEAlgorithmIdentifier(-35);
        ES512 = new COSEAlgorithmIdentifier(-36);

        keyTypeMap.put(COSEAlgorithmIdentifier.ES256, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.ES384, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.ES512, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.RS1,   COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.RS256, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.RS384, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.RS512, COSEKeyType.RSA);

        algorithmMap.put(COSEAlgorithmIdentifier.ES256, "SHA256withECDSA");
        algorithmMap.put(COSEAlgorithmIdentifier.ES384, "SHA384withECDSA");
        algorithmMap.put(COSEAlgorithmIdentifier.ES512, "SHA512withECDSA");
        algorithmMap.put(COSEAlgorithmIdentifier.RS1,   "SHA1withRSA");
        algorithmMap.put(COSEAlgorithmIdentifier.RS256, "SHA256withRSA");
        algorithmMap.put(COSEAlgorithmIdentifier.RS384, "SHA384withRSA");
        algorithmMap.put(COSEAlgorithmIdentifier.RS512, "SHA512withRSA");

        messageDigestAlgorithmMap.put(COSEAlgorithmIdentifier.ES256, "SHA-256");
        messageDigestAlgorithmMap.put(COSEAlgorithmIdentifier.ES384, "SHA-384");
        messageDigestAlgorithmMap.put(COSEAlgorithmIdentifier.ES512, "SHA-512");
        messageDigestAlgorithmMap.put(COSEAlgorithmIdentifier.RS1,   "SHA-1");
        messageDigestAlgorithmMap.put(COSEAlgorithmIdentifier.RS256, "SHA-256");
        messageDigestAlgorithmMap.put(COSEAlgorithmIdentifier.RS384, "SHA-384");
        messageDigestAlgorithmMap.put(COSEAlgorithmIdentifier.RS512, "SHA-512");
    }

    private final long value;

    COSEAlgorithmIdentifier(long value) {
        this.value = value;
    }

    // COSEAlgorithmIdentifier doesn't accept jcaName and messageDigestJcaName from caller for the time being
    public static COSEAlgorithmIdentifier create(long value) {
        return new COSEAlgorithmIdentifier(value);
    }

    @JsonCreator
    private static COSEAlgorithmIdentifier deserialize(long value) {
        return create(value);
    }

    @JsonValue
    public long getValue() {
        return value;
    }

    @JsonIgnore
    public COSEKeyType getKeyType(){
        return keyTypeMap.get(this);
    }

    @JsonIgnore
    public String getJcaName(){
        return algorithmMap.get(this);
    }

    @JsonIgnore
    public String getMessageDigestJcaName(){
        return messageDigestAlgorithmMap.get(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        COSEAlgorithmIdentifier that = (COSEAlgorithmIdentifier) o;
        return value == that.value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
