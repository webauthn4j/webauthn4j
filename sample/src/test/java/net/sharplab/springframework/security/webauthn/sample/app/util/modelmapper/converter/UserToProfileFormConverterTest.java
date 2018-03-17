package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.web.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.config.DomainConfig;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Test for UserToProfileFormConverter
 */
@SpringBootTest(classes = {DomainConfig.class, InfrastructureMockConfig.class})
@RunWith(SpringJUnit4ClassRunner.class)
public class UserToProfileFormConverterTest {

    @Autowired
    private ModelMapper modelMapper;

    @Test
    public void convert_test1(){

        //Input
        User original = new User();
        original.setFirstName("John");
        original.setLastName("Doe");
        original.setEmailAddress("john.doe@example.com");
        original.setPassword("$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq");
        original.setLocked(true);
        original.setPasswordAuthenticationAllowed(true);

        //When
        ProfileUpdateForm result = new ProfileUpdateForm();
        modelMapper.map(original, result);

        //Then
        assertThat(result.getFirstName()).isEqualTo("John");
        assertThat(result.getLastName()).isEqualTo("Doe");
        assertThat(result.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(result.isPasswordAuthenticationAllowed()).isTrue();
    }
}
