package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import java.security.PublicKey;

public interface CredentialPublicKey {

    boolean verifySignature(byte[] signature, byte[] data);

    PublicKey getPublicKey();
}
