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

package com.webauthn4j.util;

import com.webauthn4j.data.MessageDigestAlgorithm;
import com.webauthn4j.data.SignatureAlgorithm;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * A Utility class for signature calculation
 */
public class SignatureUtil {

    private SignatureUtil() {
    }

    public static @NotNull Signature createRS256() {
        return createSignature(SignatureAlgorithm.RS256);
    }

    public static @NotNull Signature createES256() {
        return createSignature(SignatureAlgorithm.ES256);
    }


    public static @NotNull Signature createSignature(@NotNull SignatureAlgorithm algorithm) {
        AssertUtil.notNull(algorithm, "algorithm is required; it must not be null");
        try {
            Signature signature = Signature.getInstance(algorithm.getJcaName());
            if(SignatureAlgorithm.PS256.equals(algorithm)) {
                PSSParameterSpec pssSpec = new PSSParameterSpec(MessageDigestAlgorithm.SHA256.getJcaName(), "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
                signature.setParameter(pssSpec);
            }
            else if(SignatureAlgorithm.PS384.equals(algorithm)) {
                PSSParameterSpec pssSpec = new PSSParameterSpec(MessageDigestAlgorithm.SHA384.getJcaName(), "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
                signature.setParameter(pssSpec);
            }
            else if(SignatureAlgorithm.PS512.equals(algorithm)) {
                PSSParameterSpec pssSpec = new PSSParameterSpec(MessageDigestAlgorithm.SHA512.getJcaName(), "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
                signature.setParameter(pssSpec);
            }
            return signature;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * @param algorithm signature algorithm
     * @return signature algorithm
     * @deprecated Use SignatureUtil.createSignature(SignatureAlgorithm algorithm) instead.
     */
    @Deprecated
    public static @NotNull Signature createSignature(@NotNull String algorithm) {
        AssertUtil.notNull(algorithm, "algorithm is required; it must not be null");
        try {
            return Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
