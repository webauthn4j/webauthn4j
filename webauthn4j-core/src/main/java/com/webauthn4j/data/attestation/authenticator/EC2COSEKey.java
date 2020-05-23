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

package com.webauthn4j.data.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class EC2COSEKey extends AbstractCOSEKey implements Serializable {

    @JsonProperty("-1")
    private final Curve curve;

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

    public static EC2COSEKey create(ECPrivateKey privateKey, COSEAlgorithmIdentifier alg) {
        Curve curve = getCurve(privateKey.getParams());
        byte[] d = privateKey.getS().toByteArray();
        return new EC2COSEKey(null, alg, null, curve, null, null, d);
    }

    public static EC2COSEKey create(ECPublicKey publicKey, COSEAlgorithmIdentifier alg) {
        ECPoint ecPoint = publicKey.getW();
        Curve curve = getCurve(publicKey.getParams());
        byte[] x = ECUtil.convertToFixedByteArray(curve.getSize(), ecPoint.getAffineX());
        byte[] y = ECUtil.convertToFixedByteArray(curve.getSize(), ecPoint.getAffineY());
        return new EC2COSEKey(null, alg, null, curve, x, y);
    }

    public static EC2COSEKey create(KeyPair keyPair, COSEAlgorithmIdentifier alg) {
        if (keyPair != null && keyPair.getPrivate() instanceof ECPrivateKey && keyPair.getPublic() instanceof ECPublicKey) {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
            ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
            ECPoint ecPoint = ecPublicKey.getW();
            Curve curve = getCurve(ecPrivateKey.getParams());
            byte[] x = ECUtil.convertToFixedByteArray(curve.getSize(), ecPoint.getAffineX());
            byte[] y = ECUtil.convertToFixedByteArray(curve.getSize(), ecPoint.getAffineY());
            byte[] d = ecPrivateKey.getS().toByteArray();
            return new EC2COSEKey(null, alg, null, curve, x, y, d);
        } else {
            throw new IllegalArgumentException();
        }
    }

    public static EC2COSEKey create(ECPrivateKey privateKey) {
        return create(privateKey, null);
    }

    public static EC2COSEKey create(ECPublicKey publicKey) {
        return create(publicKey, null);
    }

    public static EC2COSEKey create(KeyPair keyPair) {
        return create(keyPair, null);
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

        if (!hasPublicKey()) {
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
        if(!hasPrivateKey()){
            return null;
        }
        BigInteger s = new BigInteger(1, d);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, getCurve().getECParameterSpec());
        return ECUtil.createPrivateKey(ecPrivateKeySpec);
    }

    public boolean hasPublicKey() {
        return x != null && y != null;
    }

    public boolean hasPrivateKey() {
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

    static Curve getCurve(ECParameterSpec params) {
        if(params == null){
            throw new IllegalArgumentException("params must not be null");
        }
        else if(params.getCurve().equals(ECUtil.P_256_SPEC.getCurve())){
            return Curve.SECP256R1;
        }
        else if(params.getCurve().equals(ECUtil.P_384_SPEC.getCurve())){
            return Curve.SECP384R1;
        }
        else if(params.getCurve().equals(ECUtil.P_521_SPEC.getCurve())){
            return Curve.SECP521R1;
        }
        else {
            throw new IllegalArgumentException();
        }
    }

}
