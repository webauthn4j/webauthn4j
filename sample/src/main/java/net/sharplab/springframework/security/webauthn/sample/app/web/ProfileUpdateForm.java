package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

import javax.validation.Valid;
import java.util.List;

/**
 * Form for profile update
 */
@Data
public class ProfileUpdateForm {

    /**
     * first name
     */
    @NotEmpty
    private String  firstName;

    /**
     * last name
     */
    @NotEmpty
    private String  lastName;

    /**
     * e-mail address
     */
    @NotEmpty
    @Email
    private String  emailAddress;

    /**
     * authenticators
     */
    @Valid
    private List<AuthenticatorForm> authenticators;

    private boolean passwordAuthenticationAllowed;

}
