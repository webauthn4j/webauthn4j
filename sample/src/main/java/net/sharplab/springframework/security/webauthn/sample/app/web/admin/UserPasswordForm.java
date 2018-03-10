package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.sample.app.util.validator.EqualProperties;
import org.hibernate.validator.constraints.NotEmpty;

/**
 * Form for User password
 */
@Data
@EqualProperties(property = "rawPassword", comparingProperty = "rawPasswordRetyped")
public class UserPasswordForm {

    private String  emailAddress;

    @NotEmpty
    private String rawPassword;

    @NotEmpty
    private String rawPasswordRetyped;

}
