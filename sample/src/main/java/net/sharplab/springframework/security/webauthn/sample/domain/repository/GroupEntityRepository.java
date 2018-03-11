package net.sharplab.springframework.security.webauthn.sample.domain.repository;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * グループレポジトリ
 */
public interface GroupEntityRepository extends JpaRepository<GroupEntity, Integer> {

    Optional<GroupEntity> findOneByGroupName(String groupName);

    @Query("SELECT g FROM GroupEntity g WHERE g.groupName LIKE %:keyword% ORDER BY g.id")
    Page<GroupEntity> findAllByKeyword(Pageable pageable, @Param("keyword") String keyword);

}
