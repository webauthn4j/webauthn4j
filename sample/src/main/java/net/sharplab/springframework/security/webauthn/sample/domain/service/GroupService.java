package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

/**
 * グループサービス
 */
public interface GroupService {

    /**
     * グループを参照する
     * @param id グループID
     * @return グループ
     */
    Group findOne(int id);

    /**
     * グループを全件参照する
     * @return グループのリスト
     */
    List<Group> findAll();

    /**
     * グループを全件参照する
     * @param pageable ページング情報
     * @return グループのリスト
     */
    Page<Group> findAll(Pageable pageable);

    /**
     * キーワードにヒットするグループを全権参照する
     * @param pageable ページング情報
     * @param keyword キーワード
     * @return グループのリスト
     */
    Page<Group> findAllByKeyword(Pageable pageable, String keyword);

    /**
     * グループを作成する
     * @param user グループ
     * @return 作成されたグループ
     */
    Group create(Group user);

    /**
     * グループを更新する
     * @param user グループ
     */
    void update(Group user);

    /**
     * グループを削除する
     * @param id グループID
     */
    void delete(int id);

}
