package net.sharplab.springframework.security.webauthn.sample.app.api.admin;

import lombok.Data;

/**
 * Candidate User Dto
 */
@Data
public class CandidateUserDto {
    private int id;
    private String fullname;
}
