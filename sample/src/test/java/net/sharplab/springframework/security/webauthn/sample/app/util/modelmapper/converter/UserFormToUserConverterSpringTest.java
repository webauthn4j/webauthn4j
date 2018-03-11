package net.sharplab.springframework.security.webauthn.sample.app.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.sample.app.config.ModelMapperAppConfig;
import net.sharplab.springframework.security.webauthn.sample.app.config.WebSecurityConfig;
import net.sharplab.springframework.security.webauthn.sample.app.web.admin.UserForm;
import net.sharplab.springframework.security.webauthn.sample.domain.config.DomainConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * UserFormToUserConverterのテスト
 */
@SpringBootTest
@RunWith(SpringRunner.class)
@ContextConfiguration
public class UserFormToUserConverterSpringTest {

    @Autowired
    private ModelMapper modelMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void convert_test(){

        //Input
        UserForm original = new UserForm();
        original.setUserHandle("");
        original.setFirstName("John");
        original.setLastName("Doe");
        original.setEmailAddress("john.doe@example.com");
        original.setRawPassword("rawPassword");
        original.setRawPasswordRetyped("rawPasswordRetyped");
        original.setLocked(true);
        original.setPasswordAuthenticationAllowed(true);

        //When
        User result = new User();
        modelMapper.map(original, result);
        //Then
        assertThat(result.getUserHandle()).hasSize(0);
        assertThat(result.getFirstName()).isEqualTo("John");
        assertThat(result.getLastName()).isEqualTo("Doe");
        assertThat(result.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(passwordEncoder.matches("rawPassword", result.getPassword())).isTrue();
        assertThat(result.isLocked()).isTrue();
        assertThat(result.isPasswordAuthenticationAllowed()).isTrue();
    }

}
