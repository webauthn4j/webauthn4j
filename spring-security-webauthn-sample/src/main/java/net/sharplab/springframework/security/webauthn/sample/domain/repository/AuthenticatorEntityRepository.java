package net.sharplab.springframework.security.webauthn.sample.domain.repository;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Created by ynojima on 2017/07/02.
 */
public interface AuthenticatorEntityRepository extends JpaRepository<AuthenticatorEntity, Integer> {

    @Query("SELECT authenticator FROM AuthenticatorEntity authenticator WHERE authenticator.attestedCredentialData.credentialId = :credentialId")
    AuthenticatorEntity findOneByCredentialId(@Param("credentialId") byte[] credentialId);
}
