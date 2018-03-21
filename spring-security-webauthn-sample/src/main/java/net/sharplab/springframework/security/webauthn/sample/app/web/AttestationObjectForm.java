package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;
import com.webauthn4j.webauthn.attestation.WebAuthnAttestationObject;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * Form for AttestationObject
 */
@Data
public class AttestationObjectForm {

    @NotNull
    @Valid
    private WebAuthnAttestationObject attestationObject;
    @NotNull
    private String attestationObjectBase64;
}
