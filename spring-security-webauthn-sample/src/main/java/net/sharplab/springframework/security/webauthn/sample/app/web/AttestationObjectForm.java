package net.sharplab.springframework.security.webauthn.sample.app.web;

import com.webauthn4j.attestation.AttestationObject;
import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * Form for AttestationObject
 */
@Data
public class AttestationObjectForm {

    @NotNull
    @Valid
    private AttestationObject attestationObject;
    @NotNull
    private String attestationObjectBase64;
}
