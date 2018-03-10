package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness;

import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;

/**
 * Created by ynojima on 2017/09/21.
 */
public interface AttestationStatementTrustworthinessValidator {

    void validate(WebAuthnAttestationStatement attestationStatement);
}
