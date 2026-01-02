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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.exc.InvalidFormatException;

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
    private static final String JCA_RSA_SSA_PSS = "RSASSA-PSS";

    private static final String SHA_256_WITH_RSA_PSS = "SHA256withRSA/PSS";
    private static final String SHA_384_WITH_RSA_PSS = "SHA384withRSA/PSS";
    private static final String SHA_512_WITH_RSA_PSS = "SHA512withRSA/PSS";

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
    public static final SignatureAlgorithm PS256 = new SignatureAlgorithm(JCA_RSA_SSA_PSS, SHA256);
    public static final SignatureAlgorithm PS384 = new SignatureAlgorithm(JCA_RSA_SSA_PSS, SHA384);
    public static final SignatureAlgorithm PS512 = new SignatureAlgorithm(JCA_RSA_SSA_PSS, SHA512);

    private final String jcaName;
    private final MessageDigestAlgorithm messageDigestAlgorithm;

    private SignatureAlgorithm(@NotNull String jcaName, @NotNull MessageDigestAlgorithm messageDigestAlgorithm) {
        this.jcaName = jcaName;
        this.messageDigestAlgorithm = messageDigestAlgorithm;
    }

    @Deprecated
    public static SignatureAlgorithm create(@NotNull String value) {
        switch (value) {
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
            case JCA_RSA_SSA_PSS:
                throw new IllegalArgumentException(String.format("value %s is not supported by SignatureAlgorithm.create(value). Use SignatureAlgorithm.create(jcaName, messageDigestJcaName) instead.", value));
            default:
                throw new IllegalArgumentException(String.format("value %s is not supported.", value));
        }
    }

    public static SignatureAlgorithm create(@NotNull String jcaName, @NotNull String messageDigestJcaName) {
        return new SignatureAlgorithm(jcaName, MessageDigestAlgorithm.create(messageDigestJcaName));
    }

    @SuppressWarnings("unused")
    @JsonCreator
    static @NotNull SignatureAlgorithm deserialize(String value) throws InvalidFormatException {
        try {
            switch (value) {
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
                case SHA_256_WITH_RSA_PSS:
                    return PS256;
                case SHA_384_WITH_RSA_PSS:
                    return PS384;
                case SHA_512_WITH_RSA_PSS:
                    return PS512;
                case JCA_RSA_SSA_PSS:
                    throw new IllegalArgumentException(String.format("value %s is not valid text representation of SignatureAlgorithm.", value));
                default:
                    throw new IllegalArgumentException(String.format("value %s is not supported.", value));
            }
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, SignatureAlgorithm.class);
        }
    }

    /**
     * Convert SignatureAlgorithm into text representation
     * In the earlier implementation, jcaName was used as a serialized text representation directly.
     * However, since jcaName of RSA-PSS does not contain the message digest algorithm, a custom string different from jcaName is used.
     *
     * @return text representation of SignatureAlgorithm
     */
    @JsonValue
    public @NotNull String serialize() {
        if(jcaName.equals(JCA_RSA_SSA_PSS)){
            if (messageDigestAlgorithm.equals(SHA256)){
                return SHA_256_WITH_RSA_PSS;
            }
            else if (messageDigestAlgorithm.equals(SHA384)){
                return SHA_384_WITH_RSA_PSS;
            }
            else if (messageDigestAlgorithm.equals(SHA512)){
                return SHA_512_WITH_RSA_PSS;
            }
            else{
                throw new IllegalStateException("Unexpected messageDigestAlgorithm is specified");
            }
        }
        else{
            return jcaName;
        }
    }

    public @NotNull String getJcaName() {
        return jcaName;
    }

    public @NotNull MessageDigestAlgorithm getMessageDigestAlgorithm() {
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

    /**
     * @return COSEAlgorithmIdentifier style text representation of SignatureAlgorithm
     */
    @Override
    public String toString() {
        String value = serialize();
        switch (value) {
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
            case SHA_256_WITH_RSA_PSS:
                return "PS256";
            case SHA_384_WITH_RSA_PSS:
                return "PS384";
            case SHA_512_WITH_RSA_PSS:
                return "PS512";
            default:
                return "Unknown value: " + value;
        }
    }
}
