package net.sharplab.springframework.security.webauthn.sample.domain.test;


import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authority;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;

import java.util.Collections;
import java.util.List;

/**
 * フィクスチャプロバイダ
 */
public class FixtureProvider {

    public static User createUser(){
        User user = new User();
        List<User> users = Collections.singletonList(user);
        Authority authority = new Authority();
        Group group = new Group();
        Authority groupAuthority = new Authority();

        user.setId(1);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setEmailAddress("john.doe@examle.com");
        user.setPassword("dummy");
        user.setAuthorities(Collections.singletonList(authority));
        user.setGroups(Collections.singletonList(group));
        user.setLocked(false);

        authority.setId(1);
        authority.setAuthority("ROLE_USER_MANAGEMENT");
        authority.setUsers(users);

        group.setId(1);
        group.setGroupName("admin");
        group.setUsers(Collections.singletonList(user));
        group.setAuthorities(Collections.singletonList(groupAuthority));

        groupAuthority.setId(1);
        groupAuthority.setAuthority("ROLE_ADMIN");
        groupAuthority.setGroups(Collections.singletonList(group));

        return user;
    }

    public static UserEntity createUserEntity(){
        UserEntity user = new UserEntity();
        AuthorityEntity authority = new AuthorityEntity();
        GroupEntity group = new GroupEntity();
        AuthorityEntity groupAuthority = new AuthorityEntity();

        user.setId(1);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setEmailAddress("john.doe@examle.com");
        user.setPassword("dummy");
        user.setAuthorities(Collections.singletonList(authority));
        user.setGroups(Collections.singletonList(group));
        user.setLocked(false);

        authority.setId(1);
        authority.setAuthority("ROLE_USER_MANAGEMENT");
        authority.setUsers(Collections.singletonList(user));

        group.setId(1);
        group.setGroupName("admin");
        group.setUsers(Collections.singletonList(user));
        group.setAuthorities(Collections.singletonList(groupAuthority));

        groupAuthority.setId(1);
        groupAuthority.setAuthority("ROLE_ADMIN");
        groupAuthority.setGroups(Collections.singletonList(group));

        return user;
    }


}
