package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@Data
public class AuthenticatorUpdateForm {

    @NotNull
    private Integer id;

    @NotNull
    @NotEmpty
    private String name;

    private boolean delete;

}
