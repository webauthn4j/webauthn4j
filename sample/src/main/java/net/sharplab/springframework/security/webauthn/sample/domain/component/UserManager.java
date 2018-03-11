package net.sharplab.springframework.security.webauthn.sample.domain.component;


import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * ユーザー詳細サービス
 */
public interface UserManager extends UserDetailsService {

    /**
     * ユーザーを作成する
     * @param user ユーザー
     * @return ユーザー
     */
    User createUser(User user);

    /**
     * ユーザーを更新する
     * @param user ユーザー
     */
    void updateUser(User user);

    /**
     * ユーザーを削除する
     * @param username ユーザー名
     */
    void deleteUser(String username);

    /**
     * ユーザーを削除する
     * @param id ユーザーID
     */
    void deleteUser(int id);

    /**
     * パスワードを変更する
     * @param oldPassword 古いパスワード
     * @param newPassword 新しいパスワード
     */
    void changePassword(String oldPassword, String newPassword);

    /**
     * ユーザーの存在確認する
     * @param username ユーザー名
     * @return ユーザーが存在するか
     */
    boolean userExists(String username);

    /**
     * ユーザーを検索する
     * @param id ユーザーID
     * @return ユーザー
     */
    User findById(int id);

}
