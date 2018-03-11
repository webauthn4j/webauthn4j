package net.sharplab.springframework.security.webauthn.sample.domain.dto;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * AuthorityUpdateDto
 */
@Data
public class AuthorityUpdateDto implements Serializable{

    private int id;

    private List<Integer> users;
    private List<Integer> groups;

}
