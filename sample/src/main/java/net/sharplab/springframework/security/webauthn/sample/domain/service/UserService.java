package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

/**
 * ユーザーサービス
 */
public interface UserService {

    /**
     * ユーザーを参照する
     * @param id ユーザーID
     * @return ユーザー
     */
    User findOne(int id);

    /**
     * ユーザーを全件参照する
     * @return ユーザーのリスト
     */
    List<User> findAll();

    /**
     * ユーザーを全件参照する
     * @param pageable ページング情報
     * @return ユーザーのリスト
     */
    Page<User> findAll(Pageable pageable);

    /**
     * キーワードにヒットするユーザーを全権参照する
     * @param pageable ページング情報
     * @param keyword キーワード
     * @return ユーザーのリスト
     */
    Page<User> findAllByKeyword(Pageable pageable, String keyword);

    /**
     * ユーザーを作成する
     * @param user ユーザー
     * @return 作成されたユーザー
     */
    User create(User user);

    /**
     * ユーザーを更新する
     * @param user ユーザー
     */
    void update(User user);

    /**
     * ユーザーを削除する
     * @param id ユーザーID
     */
    void delete(int id);

}
