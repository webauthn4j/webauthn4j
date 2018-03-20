package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.sample.app.util.validator.EqualProperties;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorForm;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

import javax.validation.Valid;
import java.util.List;

/**
 * Form for User
 */
@Data
@EqualProperties(property = "rawPassword", comparingProperty = "rawPasswordRetyped")
public class UserForm {

    @NotEmpty
    private String userHandle;

    @NotEmpty
    private String firstName;

    @NotEmpty
    private String lastName;

    @NotEmpty
    @Email
    private String emailAddress;

    @NotEmpty
    private String rawPassword;

    @NotEmpty
    private String rawPasswordRetyped;

    @Valid
    private List<AuthenticatorForm> authenticators;

    private boolean passwordAuthenticationAllowed;

    private boolean locked;
}
