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

import org.jetbrains.annotations.NotNull;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/**
 * A Utility class for signature calculation
 */
public class SignatureUtil {

    private SignatureUtil() {
    }

    public static @NotNull Signature createRS256() {
        return createSignature("SHA256withRSA");
    }

    public static @NotNull Signature createPS256() {
        return createSignature("SHA256withRSA/PSS");
    }

    public static @NotNull Signature createES256() {
        return createSignature("SHA256withECDSA");
    }

    public static @NotNull Signature createSignature(@NotNull String algorithm) {
        AssertUtil.notNull(algorithm, "algorithm is required; it must not be null");
        try {
            return Signature.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
