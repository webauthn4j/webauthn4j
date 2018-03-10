package net.sharplab.springframework.security.webauthn.sample.app.web;

import net.sharplab.springframework.security.webauthn.sample.app.config.AppConfig;
import net.sharplab.springframework.security.webauthn.sample.app.config.ConverterConfig;
import net.sharplab.springframework.security.webauthn.sample.app.config.TestSecurityConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManager;
import net.sharplab.springframework.security.webauthn.sample.domain.config.DomainConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.service.AuthorityService;
import net.sharplab.springframework.security.webauthn.sample.domain.service.ProfileService;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


/**
 * Test for LoginController
 */
@RunWith(SpringRunner.class)
@WebMvcTest(LoginController.class)
@Import({TestSecurityConfig.class, AppConfig.class, DomainConfig.class, InfrastructureMockConfig.class})
public class LoginControllerSpringTest {

    @MockBean
    private AuthorityService authorityService;

    @Autowired
    private MockMvc mvc;

    @Test
    public void login_test1() throws Exception{
        mvc
            .perform(get("/login"))
            .andExpect(status().isOk());
    }


}
