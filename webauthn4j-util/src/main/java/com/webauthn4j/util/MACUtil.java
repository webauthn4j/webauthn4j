/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.util;

import com.webauthn4j.util.exception.UnexpectedCheckedException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * A Utility class for Message Authentication Code(MAC) manipulation
 */
public class MACUtil {

    private MACUtil() {
    }

    public static byte[] calculateHmacSHA256(byte[] message, byte[] secret) {
        return calculateHmacSHA256(message, secret, 32);
    }

    public static byte[] calculateHmacSHA256(byte[] message, byte[] secret, int outputLength) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret, "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmac = mac.doFinal(message);
            return Arrays.copyOf(hmac, outputLength);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new UnexpectedCheckedException(e);
        }
    }
}
