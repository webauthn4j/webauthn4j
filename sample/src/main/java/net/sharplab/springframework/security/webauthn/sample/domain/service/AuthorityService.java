package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.dto.AuthorityUpdateDto;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authority;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

/**
 * 権限サービス
 */
public interface AuthorityService {
    Page<Authority> findAllByKeyword(Pageable pageable, String keyword);

    Authority findOne(Integer authorityId);

    List<Authority> findAll();

    Page<Authority> findAll(Pageable pageable);

    void update(Authority authority);

    void update(AuthorityUpdateDto authorityUpdateDto);

    Page<User> findAllCandidateUsersByKeyword(Pageable pageable, String keyword);

    Page<Group> findAllCandidateGroupsByKeyword(Pageable pageable, String keyword);
}