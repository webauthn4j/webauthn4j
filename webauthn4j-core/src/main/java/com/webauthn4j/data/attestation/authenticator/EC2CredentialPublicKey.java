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

package com.webauthn4j.data.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class EC2CredentialPublicKey extends AbstractCredentialPublicKey implements Serializable {

    @JsonProperty("-1")
    private Curve curve;

    @JsonProperty("-2")
    private byte[] x;

    @JsonProperty("-3")
    private byte[] y;

    /**
     * Constructor for public key
     *
     * @param keyId     keyId
     * @param algorithm algorithm
     * @param keyOpts   keyOpts
     * @param baseIV    baseIV
     * @param curve     curve
     * @param x         x
     * @param y         y
     */
    @SuppressWarnings("squid:S00107")
    @JsonCreator
    public EC2CredentialPublicKey(
            @JsonProperty("2") byte[] keyId,
            @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @JsonProperty("4") List<COSEKeyOperation> keyOpts,
            @JsonProperty("5") byte[] baseIV,
            @JsonProperty("-1") Curve curve,
            @JsonProperty("-2") byte[] x,
            @JsonProperty("-3") byte[] y) {
        super(keyId, algorithm, keyOpts, baseIV);
        this.curve = curve;
        this.x = x;
        this.y = y;
    }

    /**
     * create from uncompressed ECC key
     *
     * @param publicKey publicKey
     * @return {@link EC2CredentialPublicKey}
     */
    public static EC2CredentialPublicKey createFromUncompressedECCKey(byte[] publicKey) {
        if (publicKey.length != 65) {
            throw new IllegalArgumentException("publicKey must be 65 bytes length");
        }
        byte[] x = Arrays.copyOfRange(publicKey, 1, 1 + 32);
        byte[] y = Arrays.copyOfRange(publicKey, 1 + 32, 1 + 32 + 32);
        return new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                x,
                y
        );
    }

    /**
     * create from {@code ECPublicKey}
     *
     * @param publicKey publicKey
     * @return {@link EC2CredentialPublicKey}
     */
    public static EC2CredentialPublicKey create(ECPublicKey publicKey) {
        ECPoint ecPoint = publicKey.getW();
        byte[] x = ecPoint.getAffineX().toByteArray();
        byte[] y = ecPoint.getAffineY().toByteArray();
        int xOffset = x.length-32;
        int yOffset = y.length-32;
        return new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                Arrays.copyOfRange(x, xOffset, xOffset+32),
                Arrays.copyOfRange(y, yOffset, yOffset+32)
        );
    }

    @Override
    public COSEKeyType getKeyType() {
        return COSEKeyType.EC2;
    }

    public Curve getCurve() {
        return curve;
    }

    public byte[] getX() {
        return ArrayUtil.clone(x);
    }

    public byte[] getY() {
        return ArrayUtil.clone(y);
    }

    @JsonIgnore
    public byte[] getBytes() {
        byte format = 0x04;
        return ByteBuffer.allocate(1 + x.length + y.length).put(format).put(x).put(y).array();
    }

    @Override
    public PublicKey getPublicKey() {
        ECPoint ecPoint = new ECPoint(
                new BigInteger(1, getX()),
                new BigInteger(1, getY())
        );
        ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, curve.getECParameterSpec());

        return ECUtil.createPublicKey(spec);
    }

    public void validate() {
        if (getAlgorithm() == null) {
            throw new ConstraintViolationException("algorithm must not be null");
        }
        if (curve == null) {
            throw new ConstraintViolationException("curve must not be null");
        }
        if (x == null) {
            throw new ConstraintViolationException("x must not be null");
        }
        if (y == null) {
            throw new ConstraintViolationException("y must not be null");
        }
        if (x.length != 32) {
            throw new ConstraintViolationException("x must be 32 bytes");
        }
        if (y.length != 32) {
            throw new ConstraintViolationException("y must be 32 bytes");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EC2CredentialPublicKey that = (EC2CredentialPublicKey) o;
        return curve == that.curve &&
                Arrays.equals(x, that.x) &&
                Arrays.equals(y, that.y);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(super.hashCode(), curve);
        result = 31 * result + Arrays.hashCode(x);
        result = 31 * result + Arrays.hashCode(y);
        return result;
    }
}
