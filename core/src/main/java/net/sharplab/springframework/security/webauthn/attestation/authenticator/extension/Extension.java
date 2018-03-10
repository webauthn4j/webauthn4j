package net.sharplab.springframework.security.webauthn.attestation.authenticator.extension;

import java.io.Serializable;

public interface Extension extends Serializable {
    String getIdentifier();
}
