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

import com.webauthn4j.util.exception.UnexpectedCheckedException;
import org.checkerframework.checker.nullness.qual.NonNull;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HKDFUtil {

    private static final int HASH_LENGTH = 32;

    private HKDFUtil() {
    }

    /**
     * calculate HKDF with SHA256
     *
     * @param ikm          input keying material
     * @param salt         salt
     * @param info         context and application specific information
     * @param outputLength length of output keying material in bytes
     * @return output keying material
     */
    public static @NonNull byte[] calculateHKDFSHA256(@NonNull byte[] ikm, @NonNull byte[] salt, @NonNull byte[] info, int outputLength) {
        byte[] pseudoRandomKey = extract(ikm, salt);
        return expand(pseudoRandomKey, info, outputLength);
    }

    /**
     * HKDF extract
     *
     * @param ikm  input keying material
     * @param salt salt
     * @return a pseudo random key
     */
    static @NonNull byte[] extract(@NonNull byte[] ikm, @NonNull byte[] salt) {
        AssertUtil.notNull(ikm, "ikm must not be null");
        if (salt == null || salt.length == 0) {
            salt = new byte[HASH_LENGTH];
        }
        return MACUtil.calculateHmacSHA256(ikm, salt);
    }

    /**
     * HKDF extract
     *
     * @param ikm input keying material
     * @return a pseudo random key
     */
    static @NonNull byte[] extract(@NonNull byte[] ikm) {
        return extract(ikm, null);
    }

    /**
     * HKDF expand
     *
     * @param key          a pseudo random key
     * @param info         context and application specific information
     * @param outputLength length of output keying material in bytes
     * @return output keying material
     */
    static @NonNull byte[] expand(@NonNull byte[] key, @NonNull byte[] info, int outputLength) {
        AssertUtil.notNull(key, "key must not be null");
        if (outputLength <= 0) {
            throw new IllegalArgumentException("outputLength must be positive");
        }
        if (outputLength > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException("outputLength must be less than or equal to 255*HashLen");
        }

        if (info == null) {
            info = new byte[0];
        }

        int n = (outputLength % HASH_LENGTH == 0) ?
                outputLength / HASH_LENGTH :
                (outputLength / HASH_LENGTH) + 1;

        byte[] hashRound = new byte[0];

        ByteBuffer generatedBytes = ByteBuffer.allocate(Math.multiplyExact(n, HASH_LENGTH));

        Mac mac = createMac(key);

        for (int roundNum = 1; roundNum <= n; roundNum++) {
            mac.reset();
            byte[] secret = ByteBuffer
                    .allocate(hashRound.length + info.length + 1)
                    .put(hashRound).put(info).put((byte) roundNum)
                    .array();
            hashRound = mac.doFinal(secret);
            generatedBytes.put(hashRound);
        }

        byte[] result = new byte[outputLength];
        generatedBytes.rewind();
        generatedBytes.get(result, 0, outputLength);
        return result;
    }

    private static @NonNull Mac createMac(@NonNull byte[] key) {
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

}
