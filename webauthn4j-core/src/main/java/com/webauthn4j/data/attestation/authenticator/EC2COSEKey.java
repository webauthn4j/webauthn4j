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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class EC2COSEKey extends AbstractCOSEKey implements Serializable {

    @JsonProperty("-1")
    private Curve curve;

    @JsonProperty("-2")
    private byte[] x;

    @JsonProperty("-3")
    private byte[] y;

    @JsonProperty("-4")
    private byte[] d;

    /**
     * Constructor for key pair
     *
     * @param keyId     keyId
     * @param algorithm algorithm
     * @param keyOps    keyOps
     * @param curve     curve
     * @param x         x
     * @param y         y
     * @param d         d
     */
    @SuppressWarnings("squid:S00107")
    @JsonCreator
    public EC2COSEKey(
            @JsonProperty("2") byte[] keyId,
            @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @JsonProperty("-1") Curve curve,
            @JsonProperty("-2") byte[] x,
            @JsonProperty("-3") byte[] y,
            @JsonProperty("-4") byte[] d) {
        super(keyId, algorithm, keyOps, null);
        this.curve = curve;
        this.x = x;
        this.y = y;
        this.d = d;
    }

    /**
     * Constructor for public key
     *
     * @param keyId     keyId
     * @param algorithm algorithm
     * @param keyOps    keyOps
     * @param curve     curve
     * @param x         x
     * @param y         y
     */
    @SuppressWarnings("squid:S00107")
    public EC2COSEKey(
            @JsonProperty("2") byte[] keyId,
            @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @JsonProperty("-1") Curve curve,
            @JsonProperty("-2") byte[] x,
            @JsonProperty("-3") byte[] y) {
        super(keyId, algorithm, keyOps, null);
        this.curve = curve;
        this.x = x;
        this.y = y;
    }

    /**
     * Constructor for public key
     *
     * @param keyId     keyId
     * @param algorithm algorithm
     * @param keyOps    keyOps
     * @param curve     curve
     * @param d         d
     */
    @SuppressWarnings("squid:S00107")
    public EC2COSEKey(
            @JsonProperty("2") byte[] keyId,
            @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @JsonProperty("-1") Curve curve,
            @JsonProperty("-2") byte[] d) {
        super(keyId, algorithm, keyOps, null);
        this.curve = curve;
        this.d = d;
    }

    /**
     * create from uncompressed ECC 256-bit key
     *
     * @param publicKey publicKey
     * @return {@link EC2COSEKey}
     */
    public static EC2COSEKey createFromUncompressedECCKey(byte[] publicKey) {
        if (publicKey.length != 65) {
            throw new IllegalArgumentException("publicKey must be 65 bytes length");
        }
        byte[] x = Arrays.copyOfRange(publicKey, 1, 1 + 32);
        byte[] y = Arrays.copyOfRange(publicKey, 1 + 32, 1 + 32 + 32);
        return new EC2COSEKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                Curve.SECP256R1,
                x,
                y,
                null
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

    public byte[] getD() {
        return ArrayUtil.clone(d);
    }

    @Override
    public PublicKey getPublicKey() {

        if(!hasPublicKey()){
            return null;
        }

        ECPoint ecPoint = new ECPoint(
                new BigInteger(1, getX()),
                new BigInteger(1, getY())
        );
        ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, curve.getECParameterSpec());

        return ECUtil.createPublicKey(spec);
    }

    @Override
    public PrivateKey getPrivateKey() {
        throw new NotImplementedException();
    }

    public boolean hasPublicKey(){
        return x != null && y != null;
    }

    public boolean hasPrivateKey(){
        return d != null;
    }

    public void validate() {
        if (getAlgorithm() == null) {
            throw new ConstraintViolationException("algorithm must not be null");
        }
        if (curve == null) {
            throw new ConstraintViolationException("curve must not be null");
        }
        if (d != null) {
            return;
        }
        if (!hasPublicKey() && !hasPrivateKey()) {
            throw new ConstraintViolationException("x, y or d must be present");
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
        EC2COSEKey that = (EC2COSEKey) o;
        return curve == that.curve &&
                Arrays.equals(x, that.x) &&
                Arrays.equals(y, that.y) &&
                Arrays.equals(d, that.d);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), curve);
        result = 31 * result + Arrays.hashCode(x);
        result = 31 * result + Arrays.hashCode(y);
        result = 31 * result + Arrays.hashCode(d);
        return result;
    }
}
