package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorForm;
import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.Valid;
import java.util.List;

/**
 * Form for User Update
 */
@Data
public class UserUpdateForm {

    @NotEmpty
    private String  firstName;

    @NotEmpty
    private String  lastName;

    @NotEmpty
    @Email
    private String  emailAddress;

    @Valid
    private List<AuthenticatorForm> authenticators;

    private boolean passwordAuthenticationAllowed;

    private boolean locked;
}
