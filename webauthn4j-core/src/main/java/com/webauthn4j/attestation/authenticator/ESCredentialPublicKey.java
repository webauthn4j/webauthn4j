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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Objects;

public class ESCredentialPublicKey extends AbstractCredentialPublicKey implements Serializable {

    @JsonProperty("3")
    private ESSignatureAlgorithm algorithm;

    @JsonProperty("-1")
    private Curve curve;
    @JsonProperty("-2")
    private byte[] x;
    @JsonProperty("-3")
    private byte[] y;
    @JsonProperty("-4")
    private byte[] d;

    public ESCredentialPublicKey(){super();}

    public ESCredentialPublicKey(int keyType, byte[] keyId, int[] keyOpts, byte[] baseIV,
                                 ESSignatureAlgorithm algorithm, Curve curve, byte[] x, byte[] y, byte[] d) {
        super(keyType, keyId, keyOpts, baseIV);
        this.algorithm = algorithm;
        this.curve = curve;
        this.x = x;
        this.y = y;
        this.d = d;
    }

    public ESSignatureAlgorithm getAlgorithm() {
        return algorithm;
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

    public byte[] getD() {
        return d;
    }

    @Override
    protected String getAlgorithmName() {
        return algorithm.getName();
    }

    @Override
    public PublicKey getPublicKey() {
        ECPoint ecPoint = new ECPoint(
                new BigInteger(1, getX()),
                new BigInteger(1, getY())
        );

        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
            parameters.init(new ECGenParameterSpec(curve.getName()));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPublicKeySpec spec = new ECPublicKeySpec(
                    ecPoint,
                    ecParameterSpec
            );
            KeyFactory factory = KeyFactory.getInstance("EC");
            return factory.generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException | InvalidParameterSpecException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ESCredentialPublicKey that = (ESCredentialPublicKey) o;
        return curve == that.curve &&
                Arrays.equals(x, that.x) &&
                Arrays.equals(y, that.y) &&
                Arrays.equals(d, that.d) &&
                Objects.equals(algorithm, that.algorithm);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(curve, algorithm);
        result = 31 * result + Arrays.hashCode(x);
        result = 31 * result + Arrays.hashCode(y);
        result = 31 * result + Arrays.hashCode(d);
        return result;
    }
}
