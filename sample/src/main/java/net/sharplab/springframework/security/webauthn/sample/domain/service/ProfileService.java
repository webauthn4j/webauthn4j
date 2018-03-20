package net.sharplab.springframework.security.webauthn.sample.domain.service;


import net.sharplab.springframework.security.webauthn.sample.domain.model.User;

/**
 * プロフィールサービス
 */
public interface ProfileService {

    /**
     * ユーザーを検索する
     *
     * @param id ユーザーID
     * @return ユーザー
     */
    User findOne(int id);

    /**
     * ユーザーを更新する
     *
     * @param user ユーザー
     */
    void update(User user);
}
