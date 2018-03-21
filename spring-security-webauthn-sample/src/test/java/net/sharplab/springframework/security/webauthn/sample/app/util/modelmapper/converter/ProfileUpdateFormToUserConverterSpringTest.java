package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.web.ProfileUpdateForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for ProfileFormToUserConverter
 */
@SpringBootTest
@RunWith(SpringRunner.class)
public class ProfileUpdateFormToUserConverterSpringTest {

    @Autowired
    private ModelMapper modelMapper;


    @Test
    public void convert_test(){

        //Input
        ProfileUpdateForm original = new ProfileUpdateForm();
        original.setFirstName("John");
        original.setLastName("Doe");
        original.setEmailAddress("john.doe@example.com");
        original.setPasswordAuthenticationAllowed(true);

        //When
        User result = new User();
        modelMapper.map(original, result);

        //Then
        assertThat(result.getFirstName()).isEqualTo("John");
        assertThat(result.getLastName()).isEqualTo("Doe");
        assertThat(result.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(result.isPasswordAuthenticationAllowed()).isTrue();
    }


}
