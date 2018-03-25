package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorUpdateForm;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

import javax.validation.Valid;
import java.util.List;

/**
 * Form for User Update
 */
@Data
public class UserUpdateForm {

    private String userHandle;

    @NotEmpty
    private String firstName;

    @NotEmpty
    private String lastName;

    @NotEmpty
    @Email
    private String emailAddress;

    @Valid
    private List<AuthenticatorUpdateForm> authenticators;

    @Valid
    private List<AuthenticatorCreateForm> newAuthenticators;

    private boolean passwordAuthenticationAllowed;

    private boolean locked;
}
