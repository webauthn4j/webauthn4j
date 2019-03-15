package com.webauthn4j.util;

import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.util.jws.JWAIdentifier;
import com.webauthn4j.validator.exception.BadSignatureException;

import java.security.*;

public final class Signature {
    public static class SignatureVerifierBuilder {
        private String algorithm;
        private PublicKey publicKey;
        private byte[] data;

        private SignatureVerifierBuilder(String identifier) {
            this.algorithm = identifier;
        }

        public static SignatureVerifierBuilder forAlgorithm(COSEAlgorithmIdentifier identifier) {
            return new SignatureVerifierBuilder(identifier.getJcaName());
        }

        public static SignatureVerifierBuilder forAlgorithm(JWAIdentifier identifier) {
            return new SignatureVerifierBuilder(identifier.getJcaName());
        }

        public SignatureVerifierBuilder publicKey(PublicKey publicKey) {
            this.publicKey = publicKey;

            return this;
        }

        public SignatureVerifierBuilder update(byte[] data) {
            this.data = data;

            return this;
        }

        public boolean verify(byte[] signature) {
            try {
                java.security.Signature verifier = java.security.Signature.getInstance(this.algorithm);
                verifier.initVerify(publicKey);
                verifier.update(data);
                return verifier.verify(signature);
            } catch (SecurityException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new BadSignatureException("Could not verify signature", e);
            }
        }
    }

    public static class SignatureBuilder {
        private String algorithm;
        private PrivateKey privateKey;
        private byte[] data;


        private SignatureBuilder(String identifier) {
            this.algorithm = identifier;
        }

        public static SignatureBuilder forAlgorithm(COSEAlgorithmIdentifier identifier) {
            return new SignatureBuilder(identifier.getJcaName());
        }

        public static SignatureBuilder forAlgorithm(JWAIdentifier identifier) {
            return new SignatureBuilder(identifier.getJcaName());
        }

        public SignatureBuilder privateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;

            return this;
        }

        public SignatureBuilder data(byte[] data) {
            this.data = data;

            return this;
        }

        public byte[] sign() throws SignatureException {
            try {
                java.security.Signature signature = java.security.Signature.getInstance(algorithm);
                signature.initSign(privateKey);
                signature.update(data);
                return signature.sign();
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new SignatureException(e);
            }
        }

    }
}
