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

package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonProperty;
import net.sharplab.springframework.security.webauthn.exception.UnsupportedArgumentException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

public class RSCredentialPublicKey extends AbstractCredentialPublicKey {

    protected transient MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @JsonProperty("-1")
    private byte[] n;
    @JsonProperty("-2")
    private byte[] e;

    public byte[] getN() {
        return n;
    }

    public void setN(byte[] n) {
        this.n = n;
    }

    public byte[] getE() {
        return e;
    }

    public void setE(byte[] e) {
        this.e = e;
    }

    @Override
    public PublicKey getPublicKey() {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                new BigInteger(1, getN()),
                new BigInteger(1, getE())
        );
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (Exception ex) {
            throw new UnsupportedOperationException(ex);
        }
    }

    @Override
    protected String getAlgorithmName() {
        int alg = getAlgorithm();
        switch (alg) {
            case -257:
                return "SHA256withRSA";
            default:
                throw new UnsupportedArgumentException(messages.getMessage(
                        "RSCredentialPublicKey.unsupportedSignatureAlgorithm",
                        "Signature algorithm is not supported"));
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RSCredentialPublicKey that = (RSCredentialPublicKey) o;
        return Arrays.equals(n, that.n) &&
                Arrays.equals(e, that.e);
    }

    @Override
    public int hashCode() {

        int result = Arrays.hashCode(n);
        result = 31 * result + Arrays.hashCode(e);
        return result;
    }
}
