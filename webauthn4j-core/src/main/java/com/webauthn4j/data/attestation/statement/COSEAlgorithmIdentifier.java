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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.webauthn4j.data.SignatureAlgorithm;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardDeserializer;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardSerializer;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = ModuleNotRegisteredGuardSerializer.class)
@JsonDeserialize(using = ModuleNotRegisteredGuardDeserializer.class)
public class COSEAlgorithmIdentifier {

    public static final COSEAlgorithmIdentifier RS1;
    public static final COSEAlgorithmIdentifier RS256;
    public static final COSEAlgorithmIdentifier RS384;
    public static final COSEAlgorithmIdentifier RS512;
    public static final COSEAlgorithmIdentifier ES256;
    public static final COSEAlgorithmIdentifier ES384;
    public static final COSEAlgorithmIdentifier ES512;
    public static final COSEAlgorithmIdentifier ESP256;
    public static final COSEAlgorithmIdentifier ESP384;
    public static final COSEAlgorithmIdentifier ESP512;
    /**
     * EdDSA is a polymorphic algorithm identifier that does not specify a curve.
     * WebAuthn Level 3 §5.8.5 restricts COSEAlgorithmIdentifier.EdDSA(-8) to the Ed25519 curve (crv=6),
     * so this identifier is treated as equivalent to {@link #Ed25519} for
     * signature verification purposes.
     * For Ed448, use {@link #Ed448} instead.
     *
     * <p>In {@code pubKeyCredParams}, this identifier is preferred over {@link #Ed25519}
     * for backward compatibility, as many existing authenticators support -8 but not -19.
     *
     * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier">WebAuthn Level 3 §5.8.5</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9864.html">RFC 9864</a>
     */
    public static final COSEAlgorithmIdentifier EdDSA;
    public static final COSEAlgorithmIdentifier Ed25519;
    public static final COSEAlgorithmIdentifier Ed448;
    public static final COSEAlgorithmIdentifier PS256;
    public static final COSEAlgorithmIdentifier PS384;
    public static final COSEAlgorithmIdentifier PS512;
    /**
     * ML-DSA-44 is only supported on JDK 24 or later
     */
    public static final COSEAlgorithmIdentifier ML_DSA_44;
    /**
     * ML-DSA-65 is only supported on JDK 24 or later
     */
    public static final COSEAlgorithmIdentifier ML_DSA_65;
    /**
     * ML-DSA-87 is only supported on JDK 24 or later
     */
    public static final COSEAlgorithmIdentifier ML_DSA_87;

    private static final Map<COSEAlgorithmIdentifier, COSEKeyType> keyTypeMap = new HashMap<>();
    private static final Map<COSEAlgorithmIdentifier, SignatureAlgorithm> algorithmMap = new HashMap<>();
    private static final Map<SignatureAlgorithm, COSEAlgorithmIdentifier> reverseAlgorithmMap = new HashMap<>();

    static {
        RS1 = new COSEAlgorithmIdentifier(-65535);
        RS256 = new COSEAlgorithmIdentifier(-257);
        RS384 = new COSEAlgorithmIdentifier(-258);
        RS512 = new COSEAlgorithmIdentifier(-259);
        ES256 = new COSEAlgorithmIdentifier(-7);
        ES384 = new COSEAlgorithmIdentifier(-35);
        ES512 = new COSEAlgorithmIdentifier(-36);
        EdDSA = new COSEAlgorithmIdentifier(-8);
        PS256 = new COSEAlgorithmIdentifier(-37);
        PS384 = new COSEAlgorithmIdentifier(-38);
        PS512 = new COSEAlgorithmIdentifier(-39);
        ML_DSA_44 = new COSEAlgorithmIdentifier(-48);
        ML_DSA_65 = new COSEAlgorithmIdentifier(-49);
        ML_DSA_87 = new COSEAlgorithmIdentifier(-50);
        ESP256 = new COSEAlgorithmIdentifier(-9);
        ESP384 = new COSEAlgorithmIdentifier(-51);
        ESP512 = new COSEAlgorithmIdentifier(-52);
        Ed25519 = new COSEAlgorithmIdentifier(-19);
        Ed448 = new COSEAlgorithmIdentifier(-53);

        keyTypeMap.put(COSEAlgorithmIdentifier.ES256, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.ES384, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.ES512, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.ESP256, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.ESP384, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.ESP512, COSEKeyType.EC2);
        keyTypeMap.put(COSEAlgorithmIdentifier.EdDSA, COSEKeyType.OKP);
        keyTypeMap.put(COSEAlgorithmIdentifier.Ed25519, COSEKeyType.OKP);
        keyTypeMap.put(COSEAlgorithmIdentifier.Ed448, COSEKeyType.OKP);
        keyTypeMap.put(COSEAlgorithmIdentifier.RS1, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.RS256, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.RS384, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.RS512, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.PS256, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.PS384, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.PS512, COSEKeyType.RSA);
        keyTypeMap.put(COSEAlgorithmIdentifier.ML_DSA_44, COSEKeyType.AKP);
        keyTypeMap.put(COSEAlgorithmIdentifier.ML_DSA_65, COSEKeyType.AKP);
        keyTypeMap.put(COSEAlgorithmIdentifier.ML_DSA_87, COSEKeyType.AKP);

        algorithmMap.put(COSEAlgorithmIdentifier.ES256, SignatureAlgorithm.ES256);
        algorithmMap.put(COSEAlgorithmIdentifier.ES384, SignatureAlgorithm.ES384);
        algorithmMap.put(COSEAlgorithmIdentifier.ES512, SignatureAlgorithm.ES512);
        algorithmMap.put(COSEAlgorithmIdentifier.ESP256, SignatureAlgorithm.ESP256);
        algorithmMap.put(COSEAlgorithmIdentifier.ESP384, SignatureAlgorithm.ESP384);
        algorithmMap.put(COSEAlgorithmIdentifier.ESP512, SignatureAlgorithm.ESP512);
        // WebAuthn Level 3 §5.8.5 restricts COSEAlgorithmIdentifier.EdDSA(-8) to Ed25519 curve
        algorithmMap.put(COSEAlgorithmIdentifier.EdDSA, SignatureAlgorithm.Ed25519);
        algorithmMap.put(COSEAlgorithmIdentifier.Ed25519, SignatureAlgorithm.Ed25519);
        algorithmMap.put(COSEAlgorithmIdentifier.Ed448, SignatureAlgorithm.Ed448);
        algorithmMap.put(COSEAlgorithmIdentifier.RS1, SignatureAlgorithm.RS1);
        algorithmMap.put(COSEAlgorithmIdentifier.RS256, SignatureAlgorithm.RS256);
        algorithmMap.put(COSEAlgorithmIdentifier.RS384, SignatureAlgorithm.RS384);
        algorithmMap.put(COSEAlgorithmIdentifier.RS512, SignatureAlgorithm.RS512);
        algorithmMap.put(COSEAlgorithmIdentifier.PS256, SignatureAlgorithm.PS256);
        algorithmMap.put(COSEAlgorithmIdentifier.PS384, SignatureAlgorithm.PS384);
        algorithmMap.put(COSEAlgorithmIdentifier.PS512, SignatureAlgorithm.PS512);
        algorithmMap.put(COSEAlgorithmIdentifier.ML_DSA_44, SignatureAlgorithm.ML_DSA_44);
        algorithmMap.put(COSEAlgorithmIdentifier.ML_DSA_65, SignatureAlgorithm.ML_DSA_65);
        algorithmMap.put(COSEAlgorithmIdentifier.ML_DSA_87, SignatureAlgorithm.ML_DSA_87);

        reverseAlgorithmMap.put(SignatureAlgorithm.ES256, COSEAlgorithmIdentifier.ES256);
        reverseAlgorithmMap.put(SignatureAlgorithm.ES384, COSEAlgorithmIdentifier.ES384);
        reverseAlgorithmMap.put(SignatureAlgorithm.ES512, COSEAlgorithmIdentifier.ES512);
        reverseAlgorithmMap.put(SignatureAlgorithm.Ed25519, COSEAlgorithmIdentifier.Ed25519);
        reverseAlgorithmMap.put(SignatureAlgorithm.Ed448, COSEAlgorithmIdentifier.Ed448);
        reverseAlgorithmMap.put(SignatureAlgorithm.RS1, COSEAlgorithmIdentifier.RS1);
        reverseAlgorithmMap.put(SignatureAlgorithm.RS256, COSEAlgorithmIdentifier.RS256);
        reverseAlgorithmMap.put(SignatureAlgorithm.RS384, COSEAlgorithmIdentifier.RS384);
        reverseAlgorithmMap.put(SignatureAlgorithm.RS512, COSEAlgorithmIdentifier.RS512);
        reverseAlgorithmMap.put(SignatureAlgorithm.PS256, COSEAlgorithmIdentifier.PS256);
        reverseAlgorithmMap.put(SignatureAlgorithm.PS384, COSEAlgorithmIdentifier.PS384);
        reverseAlgorithmMap.put(SignatureAlgorithm.PS512, COSEAlgorithmIdentifier.PS512);
        reverseAlgorithmMap.put(SignatureAlgorithm.ML_DSA_44, COSEAlgorithmIdentifier.ML_DSA_44);
        reverseAlgorithmMap.put(SignatureAlgorithm.ML_DSA_65, COSEAlgorithmIdentifier.ML_DSA_65);
        reverseAlgorithmMap.put(SignatureAlgorithm.ML_DSA_87, COSEAlgorithmIdentifier.ML_DSA_87);
    }

    private final long value;

    COSEAlgorithmIdentifier(long value) {
        this.value = value;
    }

    // COSEAlgorithmIdentifier doesn't accept jcaName and messageDigestJcaName from caller for the time being
    public static @NotNull COSEAlgorithmIdentifier create(long value) {
        return new COSEAlgorithmIdentifier(value);
    }

    /**
     * @deprecated The mapping from SignatureAlgorithm to COSEAlgorithmIdentifier is no longer
     * one-to-one since RFC 9864 introduced fully-specified identifiers (e.g. ESP256) that share
     * the same SignatureAlgorithm as their polymorphic counterparts (e.g. ES256).
     * Use the static constants directly (e.g. {@link #ES256}, {@link #ESP256}).
     */
    @Deprecated
    public static @NotNull COSEAlgorithmIdentifier create(@NotNull SignatureAlgorithm signatureAlgorithm) {
        COSEAlgorithmIdentifier coseAlgorithmIdentifier = reverseAlgorithmMap.get(signatureAlgorithm);
        if (coseAlgorithmIdentifier == null) {
            throw new IllegalArgumentException(String.format("SignatureAlgorithm %s is not supported.", signatureAlgorithm.getJcaName()));
        }
        return coseAlgorithmIdentifier;
    }

    public long getValue() {
        return value;
    }

    @JsonIgnore
    public @NotNull COSEKeyType getKeyType() {
        COSEKeyType coseKeyType = keyTypeMap.get(this);
        if (coseKeyType == null) {
            throw new IllegalArgumentException(String.format("COSEAlgorithmIdentifier %d is unknown.", this.getValue()));
        }
        return coseKeyType;
    }

    public @NotNull SignatureAlgorithm toSignatureAlgorithm() {
        SignatureAlgorithm signatureAlgorithm = algorithmMap.get(this);
        if (signatureAlgorithm == null) {
            throw new IllegalArgumentException(String.format("COSEAlgorithmIdentifier %d is unknown.", this.getValue()));
        }
        return signatureAlgorithm;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        COSEAlgorithmIdentifier that = (COSEAlgorithmIdentifier) o;
        return value == that.value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        if(value == RS1.value){
            return "RS1";
        }
        else if(value == RS256.value){
            return "RS256";
        }
        else if(value == RS384.value){
            return "RS384";
        }
        else if(value == RS512.value){
            return "RS512";
        }
        else if(value == ES256.value){
            return "ES256";
        }
        else if(value == ES384.value){
            return "ES384";
        }
        else if(value == ES512.value){
            return "ES512";
        }
        else if(value == ESP256.value){
            return "ESP256";
        }
        else if(value == ESP384.value){
            return "ESP384";
        }
        else if(value == ESP512.value){
            return "ESP512";
        }
        else if(value == EdDSA.value){
            return "EdDSA";
        }
        else if(value == Ed25519.value){
            return "Ed25519";
        }
        else if(value == Ed448.value){
            return "Ed448";
        }
        else if(value == PS256.value){
            return "PS256";
        }
        else if(value == PS384.value){
            return "PS384";
        }
        else if(value == PS512.value){
            return "PS512";
        }
        else if(value == ML_DSA_44.value){
            return "ML-DSA-44";
        }
        else if(value == ML_DSA_65.value){
            return "ML-DSA-65";
        }
        else if(value == ML_DSA_87.value){
            return "ML-DSA-87";
        }
        else {
            return String.format("Unknown COSEAlgorithmIdentifier(%d)", value);
        }
    }
}
