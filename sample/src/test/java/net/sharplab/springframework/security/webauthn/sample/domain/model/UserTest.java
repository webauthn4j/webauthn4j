package net.sharplab.springframework.security.webauthn.sample.domain.model;

import org.junit.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for User
 */
public class UserTest {
    @Test
    public void getter_setter_test1(){
        User user = new User();
        Group group = new Group();
        int userId = 1;
        String firstName = "John";
        String lastName = "Doe";
        String emailAddress = "john.doe@example.com";
        Authority authority = new Authority(1, "ROLE_ADMIN", Collections.singletonList(user), Collections.singletonList(group));

        user.setId(userId);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmailAddress(emailAddress);
        user.setAuthorities(Collections.singletonList(authority));
        user.setLocked(true);
        user.setPasswordAuthenticationAllowed(true);

        assertThat(user.getId()).isEqualTo(userId);
        assertThat(user.getFirstName()).isEqualTo(firstName);
        assertThat(user.getLastName()).isEqualTo(lastName);
        assertThat(user.getEmailAddress()).isEqualTo(emailAddress);
        assertThat(user.getAuthorities()).containsExactly(authority);
        assertThat(user.isLocked()).isTrue();
        assertThat(user.isPasswordAuthenticationAllowed()).isTrue();

        assertThat(user.getFullname()).isEqualTo("John Doe");
        assertThat(user.getUsername()).isEqualTo(emailAddress);
    }

}
