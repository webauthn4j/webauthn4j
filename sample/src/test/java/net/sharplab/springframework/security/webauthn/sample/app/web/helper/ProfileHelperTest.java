package net.sharplab.springframework.security.webauthn.sample.app.web.helper;

import net.sharplab.springframework.security.webauthn.sample.app.web.ProfileForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for ProfileFormToUserConverter
 */
@SpringBootTest
@RunWith(SpringRunner.class)
public class ProfileHelperTest {

    @Autowired
    private ProfileHelper profileHelper;


    @Test
    public void map_ProfileFormToUser_test(){

        //Input
        ProfileForm original = new ProfileForm();
        original.setFirstName("John");
        original.setLastName("Doe");
        original.setEmailAddress("john.doe@example.com");
        original.setPasswordAuthenticationAllowed(true);

        //When
        User result = new User();
        profileHelper.mapForUpdate(original, result);

        //Then
        assertThat(result.getFirstName()).isEqualTo("John");
        assertThat(result.getLastName()).isEqualTo("Doe");
        assertThat(result.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(result.isPasswordAuthenticationAllowed()).isTrue();
    }

    @Test
    public void map_UserToProfileForm(){

        //Input
        User original = new User();
        original.setFirstName("John");
        original.setLastName("Doe");
        original.setEmailAddress("john.doe@example.com");
        original.setPassword("$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq");
        original.setLocked(true);
        original.setPasswordAuthenticationAllowed(true);

        //When
        ProfileForm result = new ProfileForm();
        profileHelper.map(original, result);

        //Then
        assertThat(result.getFirstName()).isEqualTo("John");
        assertThat(result.getLastName()).isEqualTo("Doe");
        assertThat(result.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(result.isPasswordAuthenticationAllowed()).isTrue();
    }


}
