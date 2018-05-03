package net.sharplab.springframework.security.webauthn.sample.app.web.helper;

import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserCreateForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserPasswordForm;
import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for UserHelper
 */
@SpringBootTest
@RunWith(SpringRunner.class)
public class UserHelperTest {

    @Autowired
    private UserHelper userHelper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void map_UserCreateFormToUser(){

        //Input
        UserCreateForm original = new UserCreateForm();
        original.setUserHandle("");
        original.setFirstName("John");
        original.setLastName("Doe");
        original.setEmailAddress("john.doe@example.com");
        original.setRawPassword("rawPassword");
        original.setRawPasswordRetyped("rawPasswordRetyped");
        original.setLocked(true);
        original.setPasswordAuthenticationAllowed(true);

        //When
        User result = userHelper.mapForCreate(original);

        //Then
        assertThat(result.getUserHandle()).hasSize(0);
        assertThat(result.getFirstName()).isEqualTo("John");
        assertThat(result.getLastName()).isEqualTo("Doe");
        assertThat(result.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(passwordEncoder.matches("rawPassword", result.getPassword())).isTrue();
        assertThat(result.isLocked()).isTrue();
        assertThat(result.isPasswordAuthenticationAllowed()).isTrue();
    }

    @Test
    public void map_UserToUserCreateForm(){

        //Input
        User original = new User();
        original.setFirstName("John");
        original.setLastName("Doe");
        original.setEmailAddress("john.doe@example.com");
        original.setPassword("$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq");
        original.setLocked(true);
        original.setPasswordAuthenticationAllowed(true);

        UserUpdateForm result = new UserUpdateForm();

        //When
        userHelper.map(original, result);

        //Then
        assertThat(result.getFirstName()).isEqualTo("John");
        assertThat(result.getLastName()).isEqualTo("Doe");
        assertThat(result.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(result.isLocked()).isTrue();
        assertThat(result.isPasswordAuthenticationAllowed()).isTrue();
    }

    @Test
    public void map(){
        //Input
        User original = new User();
        original.setFirstName("John");
        original.setLastName("Doe");
        original.setEmailAddress("john.doe@example.com");
        original.setPassword("$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq");
        original.setLocked(true);
        original.setPasswordAuthenticationAllowed(true);

        UserPasswordForm result = new UserPasswordForm();

        //When
        userHelper.map(original, result);

        //Then
        assertThat(result.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(result.getRawPassword()).isNull();
        assertThat(result.getRawPasswordRetyped()).isNull();
    }
}
