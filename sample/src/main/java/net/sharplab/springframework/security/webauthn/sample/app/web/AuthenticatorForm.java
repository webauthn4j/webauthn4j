package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * AuthenticatorForm
 */
@Data
public class AuthenticatorForm {

    private Integer id;

    @NotNull
    @NotEmpty
    private String name;

    @NotNull
    @Valid
    private ClientDataForm clientData;

    @NotNull
    @Valid
    private AttestationObjectForm attestationObject;

}
