package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManager;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * プロフィールサービス
 */
@Service
@Transactional
public class ProfileServiceImpl implements ProfileService {

    private final UserManager userManager;

    /**
     * コンストラクタ
     * @param userManager ユーザーサービス
     */
    @Autowired
    public ProfileServiceImpl(UserManager userManager) {
        this.userManager = userManager;
    }


    /**
     * ユーザーを検索する
     * @param id ユーザーID
     */
    @Override
    @Transactional(readOnly = true)
    public User findOne(int id){
        return userManager.findOne(id);
    }


    /**
     * ユーザーを更新する
     * @param user ユーザー
     */
    @Override
    @Transactional
    public void update(User user){
        userManager.updateUser(user);
        //SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorityEntities()));
    }


}
