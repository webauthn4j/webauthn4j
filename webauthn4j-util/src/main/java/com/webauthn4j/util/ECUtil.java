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

package com.webauthn4j.util;

import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

/**
 * A Utility class for Elliptic Curve(EC) manipulation
 */
public class ECUtil {

    private static final SecureRandom secureRandom = new SecureRandom();

    public static final ECParameterSpec P_256_SPEC = createECParameterSpec("secp256r1");
    public static final ECParameterSpec P_384_SPEC = createECParameterSpec("secp384r1");
    public static final ECParameterSpec P_521_SPEC = createECParameterSpec("secp521r1");

    private ECUtil() {
    }

    public static byte[] createUncompressedPublicKey(ECPublicKey ecPublicKey) {
        byte[] x = convertToFixedByteArray(ecPublicKey.getW().getAffineX());
        byte[] y = convertToFixedByteArray(ecPublicKey.getW().getAffineY());

        byte format = 0x04;
        return ByteBuffer.allocate(65)
                .put(format)
                .put(x)
                .put(y)
                .array();
    }

    public static byte[] convertToFixedByteArray(BigInteger value){
        byte[] bytes = value.toByteArray();
        byte[] adjusted = new byte[32];
        if (bytes.length <= 32) {
            System.arraycopy(bytes, 0, adjusted, 32 - bytes.length, bytes.length);
        }
        else if (bytes.length == 32 + 1 && bytes[0] == 0) {
            System.arraycopy(bytes, 1, adjusted, 0, 32);
        } else {
            throw new IllegalStateException("x value is too large");
        }
        return adjusted;
    }

    public static KeyPair createKeyPair() {
        return createKeyPair((byte[]) null);
    }

    public static PublicKey createPublicKey(ECPublicKeySpec ecPublicKeySpec) {
        try {
            KeyFactory factory = KeyFactory.getInstance("EC");
            return factory.generatePublic(ecPublicKeySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    private static KeyPairGenerator createKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createKeyPair(byte[] seed, ECParameterSpec ecParameterSpec) {
        KeyPairGenerator keyPairGenerator = createKeyPairGenerator();
        SecureRandom random;
        try {
            if (seed != null) {
                random = SecureRandom.getInstance("SHA1PRNG"); // to make it deterministic
                random.setSeed(seed);
            } else {
                random = secureRandom;
            }
            keyPairGenerator.initialize(ecParameterSpec, random);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createKeyPair(byte[] seed) {
        return createKeyPair(seed, ECUtil.P_256_SPEC);
    }

    public static KeyPair createKeyPair(ECParameterSpec ecParameterSpec) {
        return createKeyPair(null, ecParameterSpec);
    }

    public static PublicKey createPublicKeyFromUncompressed(byte[] publicKey) {
        if (publicKey.length != 65) {
            throw new IllegalArgumentException("publicKey must be 65 bytes length");
        }
        return createPublicKey(Arrays.copyOfRange(publicKey, 1, 1 + 32),
                Arrays.copyOfRange(publicKey, 1 + 32, publicKey.length));
    }

    private static PublicKey createPublicKey(byte[] x, byte[] y) {
        try {
            byte[] encodedPublicKey = ByteBuffer.allocate(1 + x.length + y.length).put(new byte[] {0x04}).put(x).put(y).array();
            ECPoint point = createECPoint(encodedPublicKey);
            return KeyFactory.getInstance("ECDSA").generatePublic(new ECPublicKeySpec(point, ECUtil.P_256_SPEC));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    private static ECPoint createECPoint(byte[] publicKey){
        byte[] x = Arrays.copyOfRange(publicKey, 1, 1 + 32);
        byte[] y = Arrays.copyOfRange(publicKey, 1 + 32, 1 + 32 + 32);
        return new ECPoint(
                new BigInteger(1, x),
                new BigInteger(1, y)
        );
    }

    private static ECParameterSpec createECParameterSpec(String name) {
        try {
            AlgorithmParameters parameters;
            parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(name));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new UnexpectedCheckedException(e);
        }
    }
}
