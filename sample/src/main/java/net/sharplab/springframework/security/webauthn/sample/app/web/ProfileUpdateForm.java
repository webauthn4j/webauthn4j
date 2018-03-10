package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;
import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.Valid;
import java.util.List;

/**
 * Created by ynojima on 2017/09/18.
 */
@Data
public class ProfileUpdateForm {

    /**
     * 名前
     */
    @NotEmpty
    private String  firstName;

    /**
     * 苗字
     */
    @NotEmpty
    private String  lastName;

    /**
     * E-Mailアドレス
     */
    @NotEmpty
    @Email
    private String  emailAddress;

    /**
     * 認証デバイス
     */
    @Valid
    private List<AuthenticatorForm> authenticators;

}
