package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import lombok.Data;

/**
 * 権限フォーム
 */
@Data
public class AuthorityForm {

    private int[] users;

    private int[] groups;

}
