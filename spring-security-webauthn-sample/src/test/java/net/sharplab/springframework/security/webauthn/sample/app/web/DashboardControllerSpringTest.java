package net.sharplab.springframework.security.webauthn.sample.app.web;

import net.sharplab.springframework.security.webauthn.sample.app.config.AppConfig;
import net.sharplab.springframework.security.webauthn.sample.app.config.WebSecurityConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.config.DomainConfig;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test for DashboardController
 */
@RunWith(SpringRunner.class)
@WebMvcTest(DashboardController.class)
@Import(value = {WebSecurityConfig.class, AppConfig.class, DomainConfig.class, InfrastructureMockConfig.class})
@WithMockUser
public class DashboardControllerSpringTest {

    @Autowired
    private MockMvc mvc;

    @Ignore
    @Test
    @WithAnonymousUser
    public void index_test1() throws Exception{
        mvc
                .perform(get("/"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    public void index_test2() throws Exception{
        mvc
                .perform(get("/"))
                .andExpect(status().isOk());
    }

}
