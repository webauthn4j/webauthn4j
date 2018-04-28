package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.test.TestData;
import com.webauthn4j.util.*;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

@WIP
public class FIDOU2FAuthenticator {

    private PrivateKey attestationPrivateKey;
    private X509Certificate attestationPublicKeyCertificate;

    private long counter;
    private boolean countUpEnabled;

    public FIDOU2FAuthenticator(PrivateKey attestationPrivateKey, X509Certificate attestationPublicKeyCertificate, int counter){
        AssertUtil.notNull(attestationPrivateKey, "attestationPrivateKey must not be null");
        AssertUtil.notNull(attestationPublicKeyCertificate, "attestationPublicKeyCertificate must not be null");

        this.attestationPrivateKey = attestationPrivateKey;
        this.attestationPublicKeyCertificate = attestationPublicKeyCertificate;
        this.counter = counter;
    }

    public FIDOU2FAuthenticator(){
        this(TestData.AUTHENTICATOR_PRIVATE_KEY, TestData.AUTHENTICATOR_ATTESTATION_CERTIFICATE, 0);
    }

    public RegistrationResponse register(RegistrationRequest registrationRequest){

        byte[] challengeParameter = registrationRequest.getChallengeParameter();
        byte[] applicationParameter = registrationRequest.getApplicationParameter();

        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        KeyPair keyPair = getKeyPair(applicationParameter, nonce);

        byte[] rpPrivateKey = keyPair.getPrivate().getEncoded();

        byte[] message = ByteBuffer.allocate(32 + rpPrivateKey.length)
                .put(applicationParameter).put(rpPrivateKey).array();
        byte[] mac = MACUtil.caclucalteHMAC(message, attestationPrivateKey.getEncoded());
        byte[] keyHandle = ByteBuffer.allocate(64).put(nonce).put(mac).array();

        byte[] userPublicKey = getBytesFromECPublicKey((ECPublicKey)keyPair.getPublic());

        byte rfu = 0x00;

        byte[] signedData = ByteBuffer.allocate(1 + 32 + 32 + keyHandle.length + 65).put(rfu).put(applicationParameter).put(challengeParameter).put(keyHandle).put(userPublicKey).array();

        byte[] signature = calculateSignature(attestationPrivateKey, signedData);

        return new RegistrationResponse(userPublicKey, keyHandle, attestationPublicKeyCertificate, signature);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest){

        byte control = authenticationRequest.getControl();
        byte[] applicationParameter = authenticationRequest.getApplicationParameter();
        byte[] challenge = authenticationRequest.getChallenge();
        byte[] keyHandle = authenticationRequest.getKeyHandle();

        byte[] nonce = Arrays.copyOf(keyHandle, 32);
        KeyPair keyPair = getKeyPair(applicationParameter, nonce);
        countUp();
        byte userPresence = 0x01; //present
        byte[] signedData = ByteBuffer.allocate(32 + 1 + 4 + 32).put(applicationParameter).put(userPresence).put(getCounterBytes()).put(challenge).array();
        byte[] signature = calculateSignature(keyPair.getPrivate(), signedData);
        return new AuthenticationResponse(userPresence, getCounterBytes(), signature);
    }

    private byte[] getBytesFromECPublicKey(ECPublicKey ecPublicKey){
        ECPoint ecPoint = ecPublicKey.getW();
        byte type = 0x04;
        byte[] x = ecPoint.getAffineX().toByteArray();
        byte[] y = ecPoint.getAffineY().toByteArray();
        return ByteBuffer.allocate(1 + 32 + 32)
                .put(type)
                .put(Arrays.copyOfRange(x, x.length-32, x.length))
                .put(Arrays.copyOfRange(y, y.length-32, y.length))
                .array();
    }

    private KeyPair getKeyPair(byte[] applicationParameter, byte[] nonce) {
        byte[] seed = ByteBuffer.allocate(64).put(applicationParameter).put(nonce).array();
        return KeyUtil.createKeyPair(seed);
    }

    private byte[] calculateSignature(PrivateKey privateKey, byte[] signedData){
        Signature signature = SignatureUtil.createSignature("SHA256withECDSA");

        try {
            signature.initSign(privateKey);
            signature.update(signedData);
            return signature.sign();
        } catch (InvalidKeyException | SignatureException e) {
            throw new FIDOU2FException("Signature calculation error", e);
        }
    }

    private void countUp(){
        if(isCountUpEnabled()){
            counter++;
        }
    }

    private byte[] getCounterBytes(){
        return UnsignedNumberUtil.toBytes(counter);
    }


    public boolean isCountUpEnabled() {
        return countUpEnabled;
    }

    public void setCountUpEnabled(boolean countUpEnabled) {
        this.countUpEnabled = countUpEnabled;
    }
}
