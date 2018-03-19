package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import lombok.Data;

import java.util.List;

/**
 * Form for Authority
 */
@Data
public class AuthorityForm {

    private List<Integer> users;

    private List<Integer> groups;

}
