package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

/**
 * AuthenticatorCreateForm
 */
@Data
public class AuthenticatorCreateForm {

    @NotNull
    @NotEmpty
    private String name;

    @NotNull
    @Valid
    private CollectedClientDataForm clientData;

    @NotNull
    @Valid
    private AttestationObjectForm attestationObject;

    private boolean delete;

}
