package net.sharplab.springframework.security.webauthn.sample.domain.repository;


import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * ユーザーレポジトリ
 */
public interface UserEntityRepository extends JpaRepository<UserEntity, Integer> {


    @Query("SELECT user FROM UserEntity user WHERE user.firstName LIKE %:keyword% OR user.lastName LIKE %:keyword% OR user.emailAddress LIKE %:keyword% ORDER BY user.id")
    Page<UserEntity> findAllByKeyword(Pageable pageable, @Param("keyword") String keyword);

    Optional<UserEntity> findOneByEmailAddress(String emailAddress);
}
