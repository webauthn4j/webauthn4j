package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.sample.app.util.validator.EqualProperties;

import javax.validation.constraints.NotEmpty;

/**
 * Form for profile password update
 */
@Data
@EqualProperties(property = "rawPassword", comparingProperty = "rawPasswordRetyped")
public class ProfilePasswordForm {

    private String emailAddress;

    @NotEmpty
    private String rawPassword;

    @NotEmpty
    private String rawPasswordRetyped;

}