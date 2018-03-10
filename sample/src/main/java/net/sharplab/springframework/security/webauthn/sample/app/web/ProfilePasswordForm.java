package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.sample.app.util.validator.EqualProperties;
import org.hibernate.validator.constraints.NotEmpty;

/**
 * Created by ynojima on 2017/09/17.
 */
@Data
@EqualProperties(property = "rawPassword", comparingProperty = "rawPasswordRetyped")
public class ProfilePasswordForm {

    private String  emailAddress;

    @NotEmpty
    private String rawPassword;

    @NotEmpty
    private String rawPasswordRetyped;

}