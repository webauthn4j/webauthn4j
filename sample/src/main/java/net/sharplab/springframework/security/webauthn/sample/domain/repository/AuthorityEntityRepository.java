package net.sharplab.springframework.security.webauthn.sample.domain.repository;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * 権限レポジトリ
 */
public interface AuthorityEntityRepository extends JpaRepository<AuthorityEntity, Integer> {

    Optional<AuthorityEntity> findOneByAuthority(String authority);

    @Query("SELECT a FROM AuthorityEntity a WHERE a.authority LIKE %:keyword% ORDER BY a.id")
    Page<AuthorityEntity> findAllByKeyword(Pageable pageable, @Param("keyword") String keyword);
}
