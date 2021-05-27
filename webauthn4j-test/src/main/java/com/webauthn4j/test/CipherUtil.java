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

package com.webauthn4j.test;

import com.webauthn4j.util.exception.UnexpectedCheckedException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CipherUtil {
    private static final SecureRandom secureRandom = new SecureRandom();

    // https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
    private static final int IV_SIZE = 96;
    private static final int TAG_SIZE = 128;

    private CipherUtil() {
    }

    public static byte[] encrypt(byte[] data, byte[] encryptionKey) {
        try {
            final byte[] iv = new byte[IV_SIZE / 8];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(TAG_SIZE, iv));
            byte[] cipherBytes = cipher.doFinal(data);
            byte[] output = new byte[iv.length + cipherBytes.length];
            System.arraycopy(iv, 0, output, 0, iv.length);
            System.arraycopy(cipherBytes, 0, output, iv.length, cipherBytes.length);
            return output;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static byte[] decrypt(byte[] encrypted, byte[] encryptionKey) {
        try {
            byte[] iv = new byte[IV_SIZE / 8];
            byte[] cipherBytes = new byte[encrypted.length - iv.length];
            System.arraycopy(encrypted, 0, iv, 0, iv.length);
            System.arraycopy(encrypted, iv.length, cipherBytes, 0, cipherBytes.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(TAG_SIZE, iv));
            return cipher.doFinal(cipherBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new UnexpectedCheckedException(e);
        }
    }
}
