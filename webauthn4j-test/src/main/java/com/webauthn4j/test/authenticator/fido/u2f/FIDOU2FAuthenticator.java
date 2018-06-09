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

package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.test.TestData;
import com.webauthn4j.test.client.AuthenticationEmulationOption;
import com.webauthn4j.test.client.RegistrationEmulationOption;
import com.webauthn4j.util.*;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

@WIP
public class FIDOU2FAuthenticator {

    public static final byte FLAG_OFF = (byte) 0b00000000;
    public static final byte FLAG_UP = (byte) 0b00000001;

    private PrivateKey attestationPrivateKey;
    private X509Certificate attestationPublicKeyCertificate;

    private long counter;
    private boolean countUpEnabled = true;
    private byte flags = FLAG_UP;

    public FIDOU2FAuthenticator(PrivateKey attestationPrivateKey, X509Certificate attestationPublicKeyCertificate, int counter) {
        AssertUtil.notNull(attestationPrivateKey, "attestationPrivateKey must not be null");
        AssertUtil.notNull(attestationPublicKeyCertificate, "attestationPublicKeyCertificate must not be null");

        this.attestationPrivateKey = attestationPrivateKey;
        this.attestationPublicKeyCertificate = attestationPublicKeyCertificate;
        this.counter = counter;
    }

    public FIDOU2FAuthenticator() {
        this(TestData.FIDO_U2F_AUTHENTICATOR_ATTESTATION_PRIVATE_KEY, TestData.FIDO_U2F_AUTHENTICATOR_ATTESTATION_CERTIFICATE, 0);
    }

    public RegistrationResponse register(RegistrationRequest registrationRequest, RegistrationEmulationOption registrationEmulationOption) {

        byte[] challengeParameter = registrationRequest.getChallengeParameter();
        byte[] applicationParameter = registrationRequest.getApplicationParameter();

        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        KeyPair keyPair = getKeyPair(applicationParameter, nonce);

        byte[] rpPrivateKey = keyPair.getPrivate().getEncoded();

        byte[] message = ByteBuffer.allocate(32 + rpPrivateKey.length)
                .put(applicationParameter).put(rpPrivateKey).array();
        byte[] mac = MACUtil.calculateHMAC(message, attestationPrivateKey.getEncoded());
        byte[] keyHandle = ByteBuffer.allocate(64).put(nonce).put(mac).array();

        byte[] userPublicKey = getBytesFromECPublicKey((ECPublicKey) keyPair.getPublic());

        byte rfu = 0x00;

        byte[] signedData = ByteBuffer.allocate(1 + 32 + 32 + keyHandle.length + 65).put(rfu).put(applicationParameter).put(challengeParameter).put(keyHandle).put(userPublicKey).array();

        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
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

        byte[] nonce = Arrays.copyOf(keyHandle, 32);
        KeyPair keyPair = getKeyPair(applicationParameter, nonce);
        countUp();
        byte[] signedData = ByteBuffer.allocate(32 + 1 + 4 + 32).put(applicationParameter).put(flags).put(getCounterBytes()).put(challenge).array();
        byte[] signature = calculateSignature(keyPair.getPrivate(), signedData);
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
        byteBuffer.position(byteBuffer.position() + 32 - x.length);
        byteBuffer.put(x);
        byteBuffer.position(byteBuffer.position() + 32 - y.length);
        byteBuffer.put(y);
        return byteBuffer.array();
    }

    private KeyPair getKeyPair(byte[] applicationParameter, byte[] nonce) {
        byte[] seed = ByteBuffer.allocate(64).put(applicationParameter).put(nonce).array();
        return KeyUtil.createECKeyPair(seed);
    }

    private byte[] calculateSignature(PrivateKey privateKey, byte[] signedData) {
        try {
            Signature signature = SignatureUtil.createSignature("SHA256withECDSA");
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
