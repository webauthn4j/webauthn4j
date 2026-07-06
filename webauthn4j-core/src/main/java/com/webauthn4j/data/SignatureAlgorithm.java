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

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

import static com.webauthn4j.data.MessageDigestAlgorithm.*;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardDeserializer;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardSerializer;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

/**
 * Represents a signature algorithm as a pair of a JCA algorithm name and an optional pre-hash
 * (message digest) algorithm.
 * <p>
 * The {@code jcaName} is the algorithm name passed to {@link java.security.Signature#getInstance(String)}
 * (e.g., "SHA256withECDSA", "RSASSA-PSS", "ed25519").
 * <p>
 * The {@code messageDigestAlgorithm} represents the hash function applied to the message
 * <em>before</em> the core signing operation. For pre-hash signature schemes such as ECDSA and RSA,
 * this corresponds to the hash component of the composite algorithm (e.g., SHA-256 in SHA256withECDSA).
 * For RSA-PSS, it is also used to distinguish PS256/PS384/PS512, which share the same JCA name "RSASSA-PSS".
 * <p>
 * For pure signature schemes (e.g., Ed25519), the message is not pre-hashed; it is passed directly
 * to the signing function. In such cases, {@code messageDigestAlgorithm} is null.
 * Note that pure schemes may still use hash functions internally (e.g., Ed25519 uses SHA-512
 * for nonce and challenge computation), but this is not an external pre-hash step.
 */
@JsonSerialize(using = ModuleNotRegisteredGuardSerializer.class)
@JsonDeserialize(using = ModuleNotRegisteredGuardDeserializer.class)
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
     * Ed25519 is a pure signature scheme, not a pre-hash scheme like SHA256withECDSA.
     * Although SHA-512 is used internally within the Ed25519 algorithm (e.g., for nonce
     * and challenge computation), the message itself is NOT pre-hashed before signing.
     * Therefore, messageDigestAlgorithm is null.
     */
    public static final SignatureAlgorithm Ed25519 = new SignatureAlgorithm(JCA_ED_25519, null);
    public static final SignatureAlgorithm PS256 = new SignatureAlgorithm(JCA_RSA_SSA_PSS, SHA256);
    public static final SignatureAlgorithm PS384 = new SignatureAlgorithm(JCA_RSA_SSA_PSS, SHA384);
    public static final SignatureAlgorithm PS512 = new SignatureAlgorithm(JCA_RSA_SSA_PSS, SHA512);
    // RFC 9864 fully-specified aliases — cryptographically identical to ES256/ES384/ES512
    public static final SignatureAlgorithm ESP256 = ES256;
    public static final SignatureAlgorithm ESP384 = ES384;
    public static final SignatureAlgorithm ESP512 = ES512;

    private final String jcaName;
    private final @Nullable MessageDigestAlgorithm messageDigestAlgorithm;

    private SignatureAlgorithm(@NotNull String jcaName, @Nullable MessageDigestAlgorithm messageDigestAlgorithm) {
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

    /**
     * Convert SignatureAlgorithm into text representation
     * In the earlier implementation, jcaName was used as a serialized text representation directly.
     * However, since jcaName of RSA-PSS does not contain the message digest algorithm, a custom string different from jcaName is used.
     *
     * @return text representation of SignatureAlgorithm
     */
    public @NotNull String serialize() {
        if(jcaName.equals(JCA_RSA_SSA_PSS)){
            if (messageDigestAlgorithm == null){
                throw new IllegalStateException("messageDigestAlgorithm must not be null for RSA-PSS");
            }
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

    /**
     * Returns the message digest algorithm used for pre-hashing the message before signing.
     * Returns null for pure signature schemes (e.g., Ed25519) where the message is not pre-hashed.
     *
     * @return the message digest algorithm, or null for pure signature schemes
     */
    public @Nullable MessageDigestAlgorithm getMessageDigestAlgorithm() {
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
