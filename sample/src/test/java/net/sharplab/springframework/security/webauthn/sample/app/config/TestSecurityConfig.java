package net.sharplab.springframework.security.webauthn.sample.app.config;

import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManagerImpl;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * SecurityConfig for Test
 */
@Import(WebSecurityConfig.class)
@Configuration
public class TestSecurityConfig {

    @MockBean
    UserManagerImpl userManager;

}
