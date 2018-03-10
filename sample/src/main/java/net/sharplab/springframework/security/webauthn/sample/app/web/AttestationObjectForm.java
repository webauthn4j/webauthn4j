package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * Created by ynojima on 2017/08/20.
 */
@Data
public class AttestationObjectForm {

    @NotNull
    @Valid
    private WebAuthnAttestationObject attestationObject;
    @NotNull
    private String attestationObjectBase64;
}
