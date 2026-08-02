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

package com.webauthn4j.test.authenticator.u2f;

import com.webauthn4j.test.TestConstants;
import com.webauthn4j.test.authenticator.u2f.exception.FIDOU2FException;
import com.webauthn4j.test.client.AuthenticationEmulationOption;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;

public class FIDOU2FAuthenticator {

    public static final byte FLAG_OFF = (byte) 0b00000000;
    public static final byte FLAG_UP = (byte) 0b00000001; // user presence
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    // property
    private final PrivateKey attestationPrivateKey;
    private final X509Certificate attestationPublicKeyCertificate;
    private final SecretKey wrappingKey;
    private long counter;
    private byte flags = FLAG_UP;

    // feature flags
    private boolean countUpEnabled = true;

    public FIDOU2FAuthenticator(PrivateKey attestationPrivateKey, X509Certificate attestationPublicKeyCertificate, int counter) {
        AssertUtil.notNull(attestationPrivateKey, "attestationPrivateKey must not be null");
        AssertUtil.notNull(attestationPublicKeyCertificate, "attestationPublicKeyCertificate must not be null");

        this.attestationPrivateKey = attestationPrivateKey;
        this.attestationPublicKeyCertificate = attestationPublicKeyCertificate;
        this.counter = counter;
        this.wrappingKey = deriveWrappingKey(attestationPrivateKey);
    }

    public FIDOU2FAuthenticator() {
        this(TestConstants.GENERIC_2TIER_ATTESTATION_PRIVATE_KEY, TestConstants.GENERIC_2TIER_ATTESTATION_CERTIFICATE, 0);
    }

    public RegistrationResponse register(RegistrationRequest registrationRequest, RegistrationEmulationOption registrationEmulationOption) {

        byte[] challengeParameter = registrationRequest.getChallengeParameter();
        byte[] applicationParameter = registrationRequest.getApplicationParameter();

        KeyPair keyPair = ECUtil.createKeyPair();

        byte[] keyHandle = wrapPrivateKey((ECPrivateKey) keyPair.getPrivate());

        byte[] userPublicKey = getBytesFromECPublicKey((ECPublicKey) keyPair.getPublic());

        byte rfu = 0x00;

        byte[] signedData = ByteBuffer.allocate(1 + 32 + 32 + keyHandle.length + 65).put(rfu).put(applicationParameter).put(challengeParameter).put(keyHandle).put(userPublicKey).array();

        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        }
        else {
            signature = calculateSignature(attestationPrivateKey, signedData);
        }

        return new RegistrationResponse(userPublicKey, keyHandle, attestationPublicKeyCertificate, signature);
    }

    public RegistrationResponse register(RegistrationRequest registrationRequest) {
        return register(registrationRequest, new RegistrationEmulationOption());
    }


    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest, AuthenticationEmulationOption authenticationEmulationOption) {

        byte control = authenticationRequest.getControl();
        byte[] applicationParameter = authenticationRequest.getApplicationParameter();
        byte[] challenge = authenticationRequest.getChallenge();
        byte[] keyHandle = authenticationRequest.getKeyHandle();

        PrivateKey privateKey = unwrapPrivateKey(keyHandle);
        countUp();
        byte[] signedData = ByteBuffer.allocate(32 + 1 + 4 + 32).put(applicationParameter).put(flags).put(getCounterBytes()).put(challenge).array();
        byte[] signature = calculateSignature(privateKey, signedData);
        return new AuthenticationResponse(flags, getCounterBytes(), signature);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        return authenticate(authenticationRequest, new AuthenticationEmulationOption());
    }

    private byte[] getBytesFromECPublicKey(ECPublicKey ecPublicKey) {
        ECPoint ecPoint = ecPublicKey.getW();
        byte type = 0x04;
        byte[] x = ecPoint.getAffineX().toByteArray();
        byte[] y = ecPoint.getAffineY().toByteArray();
        x = Arrays.copyOfRange(x, Math.max(0, x.length - 32), x.length);
        y = Arrays.copyOfRange(y, Math.max(0, y.length - 32), y.length);
        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + 32 + 32);
        byteBuffer.put(type);
        //This cast is necessary to be complied with JDK 17 when targeting JDK 8
        ((Buffer)byteBuffer).position(((Buffer)byteBuffer).position() + 32 - x.length);
        byteBuffer.put(x);
        //This cast is necessary to be complied with JDK 17 when targeting JDK 8
        ((Buffer)byteBuffer).position(((Buffer)byteBuffer).position() + 32 - y.length);
        byteBuffer.put(y);
        return byteBuffer.array();
    }

    private static SecretKey deriveWrappingKey(PrivateKey attestationPrivateKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(attestationPrivateKey.getEncoded());
            return new SecretKeySpec(hash, "AES");
        } catch (NoSuchAlgorithmException e) {
            throw new FIDOU2FException("Failed to derive wrapping key", e);
        }
    }

    private byte[] wrapPrivateKey(ECPrivateKey privateKey) {
        try {
            byte[] scalar = ArrayUtil.convertToFixedByteArray(privateKey.getS());
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, wrappingKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(scalar);
            return ByteBuffer.allocate(GCM_IV_LENGTH + encrypted.length)
                    .put(iv).put(encrypted).array();
        } catch (GeneralSecurityException e) {
            throw new FIDOU2FException("Failed to wrap private key", e);
        }
    }

    private PrivateKey unwrapPrivateKey(byte[] keyHandle) {
        try {
            byte[] iv = Arrays.copyOf(keyHandle, GCM_IV_LENGTH);
            byte[] encrypted = Arrays.copyOfRange(keyHandle, GCM_IV_LENGTH, keyHandle.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, wrappingKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] scalar = cipher.doFinal(encrypted);
            BigInteger s = new BigInteger(1, scalar);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePrivate(new ECPrivateKeySpec(s, ECUtil.P_256_SPEC));
        } catch (GeneralSecurityException e) {
            throw new FIDOU2FException("Failed to unwrap private key", e);
        }
    }

    private byte[] calculateSignature(PrivateKey privateKey, byte[] signedData) {
        try {
            Signature signature = SignatureUtil.createES256();
            signature.initSign(privateKey);
            signature.update(signedData);
            return signature.sign();
        } catch (InvalidKeyException | SignatureException e) {
            throw new FIDOU2FException("Signature calculation error", e);
        }
    }

    private void countUp() {
        if (isCountUpEnabled()) {
            counter++;
        }
    }

    private byte[] getCounterBytes() {
        return UnsignedNumberUtil.toBytes(counter);
    }


    public boolean isCountUpEnabled() {
        return countUpEnabled;
    }

    public void setCountUpEnabled(boolean countUpEnabled) {
        this.countUpEnabled = countUpEnabled;
    }

    public byte getFlags() {
        return flags;
    }

    public void setFlags(byte flags) {
        this.flags = flags;
    }
}
