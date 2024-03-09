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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

import static com.webauthn4j.data.MessageDigestAlgorithm.*;

public class SignatureAlgorithm {

    private static final String JCA_SHA_256_WITH_ECDSA = "SHA256withECDSA";
    private static final String JCA_SHA_384_WITH_ECDSA = "SHA384withECDSA";
    private static final String JCA_SHA_512_WITH_ECDSA = "SHA512withECDSA";
    private static final String JCA_SHA_1_WITH_RSA = "SHA1withRSA";
    private static final String JCA_SHA_256_WITH_RSA = "SHA256withRSA";
    private static final String JCA_SHA_384_WITH_RSA = "SHA384withRSA";
    private static final String JCA_SHA_512_WITH_RSA = "SHA512withRSA";
    private static final String JCA_ED_25519 = "ed25519";

    public static final SignatureAlgorithm ES256 = new SignatureAlgorithm(JCA_SHA_256_WITH_ECDSA, SHA256);
    public static final SignatureAlgorithm ES384 = new SignatureAlgorithm(JCA_SHA_384_WITH_ECDSA, SHA384);
    public static final SignatureAlgorithm ES512 = new SignatureAlgorithm(JCA_SHA_512_WITH_ECDSA, SHA512);
    public static final SignatureAlgorithm RS1 = new SignatureAlgorithm(JCA_SHA_1_WITH_RSA, SHA1);
    public static final SignatureAlgorithm RS256 = new SignatureAlgorithm(JCA_SHA_256_WITH_RSA, SHA256);
    public static final SignatureAlgorithm RS384 = new SignatureAlgorithm(JCA_SHA_384_WITH_RSA, SHA384);
    public static final SignatureAlgorithm RS512 = new SignatureAlgorithm(JCA_SHA_512_WITH_RSA, SHA512);
    /**
     * Ed25519 is only supported on JDK 15 or later
     */
    public static final SignatureAlgorithm Ed25519 = new SignatureAlgorithm(JCA_ED_25519, SHA512);


    private final String jcaName;
    private final MessageDigestAlgorithm messageDigestAlgorithm;

    private SignatureAlgorithm(@NonNull String jcaName, @NonNull MessageDigestAlgorithm messageDigestAlgorithm) {
        this.jcaName = jcaName;
        this.messageDigestAlgorithm = messageDigestAlgorithm;
    }

    public static SignatureAlgorithm create(@NonNull String jcaName) {
        switch (jcaName) {
            case JCA_SHA_256_WITH_ECDSA:
                return ES256;
            case JCA_SHA_384_WITH_ECDSA:
                return ES384;
            case JCA_SHA_512_WITH_ECDSA:
                return ES512;
            case JCA_SHA_1_WITH_RSA:
                return RS1;
            case JCA_SHA_256_WITH_RSA:
                return RS256;
            case JCA_SHA_384_WITH_RSA:
                return RS384;
            case JCA_SHA_512_WITH_RSA:
                return RS512;
            case JCA_ED_25519:
                return Ed25519;
            default:
                throw new IllegalArgumentException(String.format("jcaName %s is not supported.", jcaName));
        }
    }

    public static SignatureAlgorithm create(@NonNull String jcaName, @NonNull String messageDigestJcaName) {
        return new SignatureAlgorithm(jcaName, MessageDigestAlgorithm.create(messageDigestJcaName));
    }

    @SuppressWarnings("unused")
    @JsonCreator
    private static @NonNull SignatureAlgorithm deserialize(String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, SignatureAlgorithm.class);
        }
    }

    @JsonValue
    public @NonNull String getJcaName() {
        return jcaName;
    }

    public @NonNull MessageDigestAlgorithm getMessageDigestAlgorithm() {
        return messageDigestAlgorithm;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SignatureAlgorithm that = (SignatureAlgorithm) o;
        return Objects.equals(jcaName, that.jcaName) &&
                Objects.equals(messageDigestAlgorithm, that.messageDigestAlgorithm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(jcaName, messageDigestAlgorithm);
    }

    @Override
    public String toString() {
        switch (jcaName) {
            case JCA_SHA_256_WITH_ECDSA:
                return "ES256";
            case JCA_SHA_384_WITH_ECDSA:
                return "ES384";
            case JCA_SHA_512_WITH_ECDSA:
                return "ES512";
            case JCA_SHA_1_WITH_RSA:
                return "RS1";
            case JCA_SHA_256_WITH_RSA:
                return "RS256";
            case JCA_SHA_384_WITH_RSA:
                return "RS384";
            case JCA_SHA_512_WITH_RSA:
                return "RS512";
            case JCA_ED_25519:
                return "Ed25519";
            default:
                return "Unknown jcaName: " + jcaName;
        }
    }
}
