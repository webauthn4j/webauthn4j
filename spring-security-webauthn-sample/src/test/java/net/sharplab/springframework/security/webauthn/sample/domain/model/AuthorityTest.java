package net.sharplab.springframework.security.webauthn.sample.domain.model;

import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for Authority
 */
public class AuthorityTest {

    private final Authority target = new Authority();

    @Test
    public void authority_test1(){
        int id = 1;
        User user = new User();
        List<User> users = Collections.singletonList(user);
        String authority = "ROLE_DUMMY";

        target.setId(1);
        target.setUsers(users);
        target.setAuthority(authority);
        assertThat(target.getId()).isSameAs(id);
        assertThat(target.getUsers()).isSameAs(users);
        assertThat(target.getAuthority()).isSameAs(authority);
    }

    @Test
    public void toString_test1(){
        target.setAuthority("ROLE_TEST");
        assertThat(target.toString()).isEqualTo("ROLE_TEST");
    }

}
