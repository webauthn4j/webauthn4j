package net.sharplab.springframework.security.webauthn.sample.domain.dto;

import lombok.Data;

import java.io.Serializable;

/**
 * AuthorityUpdateDto
 */
@Data
public class AuthorityUpdateDto implements Serializable{

    private int id;

    private int[] users;
    private int[] groups;

}
