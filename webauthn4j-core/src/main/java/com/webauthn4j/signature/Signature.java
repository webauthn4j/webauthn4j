package com.webauthn4j.signature;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.validator.exception.BadSignatureException;

import java.security.*;

public final class Signature {
    public static class Verifier {
        private String algorithm;
        private PublicKey publicKey;
        private byte[] data;

        private Verifier(String identifier) {
            this.algorithm = identifier;
        }

        public static Verifier forAlgorithm(COSEAlgorithmIdentifier identifier) {
            return new Verifier(identifier.getJcaName());
        }

        public static Verifier forAlgorithm(JWAIdentifier identifier) {
            return new Verifier(identifier.getJcaName());
        }

        public Verifier publicKey(PublicKey publicKey) {
            this.publicKey = publicKey;

            return this;
        }

        public Verifier update(byte[] data) {
            this.data = data;

            return this;
        }

        public boolean verify(byte[] signature) throws BadSignatureException {
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

    public static class Signer {
        private String algorithm;
        private PrivateKey privateKey;
        private byte[] data;


        private Signer(String identifier) {
            this.algorithm = identifier;
        }

        public static Signer forAlgorithm(COSEAlgorithmIdentifier identifier) {
            return new Signer(identifier.getJcaName());
        }

        public static Signer forAlgorithm(JWAIdentifier identifier) {
            return new Signer(identifier.getJcaName());
        }

        public Signer privateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;

            return this;
        }

        public Signer data(byte[] data) {
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
