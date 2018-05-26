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

package com.webauthn4j.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.COSEKeyOperation;
import com.webauthn4j.attestation.statement.COSEKeyType;
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

public class ECCredentialPublicKey extends AbstractCredentialPublicKey implements Serializable {

    @JsonProperty("-1")
    private Curve curve;

    @JsonProperty("-2")
    private byte[] x;

    @JsonProperty("-3")
    private byte[] y;

    public ECCredentialPublicKey() {
        super();
    }

    /**
     * Constructor for public key
     */
    @SuppressWarnings("squid:S00107")
    public ECCredentialPublicKey(COSEKeyType keyType, byte[] keyId, COSEAlgorithmIdentifier algorithm, COSEKeyOperation[] keyOpts, byte[] baseIV,
                                 Curve curve, byte[] x, byte[] y) {
        super(keyType, keyId, algorithm, keyOpts, baseIV);
        this.curve = curve;
        this.x = x;
        this.y = y;
    }

    /**
     * create from uncompressed ECC key
     */
    public static ECCredentialPublicKey createFromUncompressedECCKey(byte[] publicKey) {
        if (publicKey.length != 65) {
            throw new IllegalArgumentException("publicKey must be 65 bytes length");
        }
        byte[] x = Arrays.copyOfRange(publicKey, 1, 1 + 32);
        byte[] y = Arrays.copyOfRange(publicKey, 1 + 32, 1 + 32 + 32);
        return new ECCredentialPublicKey(
                COSEKeyType.EC2,
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
     */
    public static CredentialPublicKey create(ECPublicKey publicKey) {
        ECPoint ecPoint = publicKey.getW();
        byte[] x = ecPoint.getAffineX().toByteArray();
        byte[] y = ecPoint.getAffineY().toByteArray();
        return new ECCredentialPublicKey(
                COSEKeyType.EC2,
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                x,
                y
        );
    }

    public Curve getCurve() {
        return curve;
    }

    public byte[] getX() {
        return x;
    }

    public byte[] getY() {
        return y;
    }

    @Override
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

        try {
            ECParameterSpec ecParameterSpec = curve.getECParameterSpec();
            ECPublicKeySpec spec = new ECPublicKeySpec(
                    ecPoint,
                    ecParameterSpec
            );
            KeyFactory factory = KeyFactory.getInstance("EC");
            return factory.generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
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
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ECCredentialPublicKey that = (ECCredentialPublicKey) o;
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
