package com.webauthn4j.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SecureRandomFactory {
    public final static String SHA1PRNG = "SHA1PRNG";

    private final static SRI SECURE_RANDOM = new SRI(new SecureRandom());
    private static SRI STRONG_SECURE_RANDOM = null;


    public static SecureRandom createSeededSecureRandom(String algorithm, byte[] seed) throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance(algorithm);
        random.setSeed(seed);

        return random;
    }

    public static SRI getSecureRandom() {
        return SECURE_RANDOM;
    }

    public static synchronized SRI getStrongSecureRandom() {
        synchronized (SecureRandomFactory.class) {
            if (STRONG_SECURE_RANDOM == null) {
                try {
                    STRONG_SECURE_RANDOM = new SRI(SecureRandom.getInstanceStrong());
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }

            return STRONG_SECURE_RANDOM;
        }
    }

    public static class SRI {
        private SecureRandom secureRandom;

        SRI(final SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
        }

        SecureRandom get() {
            return secureRandom;
        }

        synchronized void nextBytes(byte[] bytes) {
            this.secureRandom.nextBytes(bytes);
        }

        public byte[] randomBytes(int size) {
            byte[] nonce = new byte[size];

            nextBytes(nonce);

            return nonce.clone();
        }
    }
}
