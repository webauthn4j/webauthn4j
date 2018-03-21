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

package com.webauthn4j.webauthn.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.webauthn.exception.UnsupportedArgumentException;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Objects;

@JsonIgnoreProperties({"publicKey", "curveName", "algorithmName"})
public class ESCredentialPublicKey extends AbstractCredentialPublicKey implements Serializable {

    @JsonProperty("-1")
    private int curve;
    @JsonProperty("-2")
    private byte[] x;
    @JsonProperty("-3")
    private byte[] y;
    @JsonProperty("-4")
    private byte[] d;

    public int getCurve() {
        return curve;
    }

    public void setCurve(int curve) {
        this.curve = curve;
    }

    public byte[] getX() {
        return x;
    }

    public void setX(byte[] x) {
        this.x = x;
    }

    public byte[] getY() {
        return y;
    }

    public void setY(byte[] y) {
        this.y = y;
    }

    public byte[] getD() {
        return d;
    }

    public void setD(byte[] d) {
        this.d = d;
    }

    @Override
    public PublicKey getPublicKey() {
        ECPoint ecPoint = new ECPoint(
                new BigInteger(1, getX()),
                new BigInteger(1, getY())
        );

        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
            parameters.init(new ECGenParameterSpec(getCurveName()));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPublicKeySpec spec = new ECPublicKeySpec(
                    ecPoint,
                    ecParameterSpec
            );
            KeyFactory factory = KeyFactory.getInstance("EC");
            return factory.generatePublic(spec);
        } catch (Exception ex) {
            throw new UnsupportedOperationException(ex);
        }
    }

    private String getCurveName() {
        switch (curve) {
            case 1:
                return "secp256r1";
            case 2:
                return "secp384r1";
            case 3:
                return "secp521r1";
            default:
                throw new UnsupportedArgumentException("Signature algorithm is not supported");
        }
    }

    @Override
    protected String getAlgorithmName() {
        int alg = getAlgorithm();
        switch (alg) {
            case -7:
                return "SHA256withECDSA";
            case -35:
                return "SHA384withECDSA";
            case -36:
                return "SHA512withECDSA";
            default:
                throw new UnsupportedArgumentException("Signature algorithm is not supported");
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
                Arrays.equals(d, that.d);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(curve);
        result = 31 * result + Arrays.hashCode(x);
        result = 31 * result + Arrays.hashCode(y);
        result = 31 * result + Arrays.hashCode(d);
        return result;
    }
}
