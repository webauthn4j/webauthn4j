package net.sharplab.springframework.security.webauthn.sample.app.api.admin;

import lombok.Data;

/**
 * Candidate Group Dto
 */
@Data
public class CandidateGroupDto {
    private int id;
    private String groupName;
}
