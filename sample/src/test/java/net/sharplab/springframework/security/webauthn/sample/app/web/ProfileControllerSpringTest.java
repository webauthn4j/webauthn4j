package net.sharplab.springframework.security.webauthn.sample.app.web;

import net.sharplab.springframework.security.webauthn.sample.app.config.AppConfig;
import net.sharplab.springframework.security.webauthn.sample.app.config.TestSecurityConfig;
import net.sharplab.springframework.security.webauthn.sample.app.test.WithMockUser;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.ProfileService;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;

import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test for UserController
 */
@RunWith(SpringRunner.class)
@WebMvcTest(ProfileController.class)
@Import(value = {TestSecurityConfig.class, AppConfig.class, InfrastructureMockConfig.class})
public class ProfileControllerSpringTest {
    @Autowired
    private MockMvc mvc;

    @MockBean
    ProfileService profileService;

    @Test
    @WithMockUser(id=1, firstName = "John", lastName = "Doe", emailAddress = "john.doe@example.com", authorities = {"ROLE_USER"}, authenticators = {})
    public void show_test() throws Exception{
        int userId = 1;

        User user = new User();
        user.setUserHandle(new byte[0]);
        user.setId(userId);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setEmailAddress("john.doe@example.com");
        user.setAuthenticators(Collections.emptyList());
        user.setPasswordAuthenticationAllowed(true);

        when(profileService.findOne(userId)).thenReturn(user);

        ProfileForm profileForm = new ProfileForm();
        profileForm.setUserHandle("");
        profileForm.setFirstName("John");
        profileForm.setLastName("Doe");
        profileForm.setEmailAddress("john.doe@example.com");
        profileForm.setAuthenticators(Collections.emptyList());
        profileForm.setPasswordAuthenticationAllowed(true);

        //When
        mvc
                .perform(get("/profile/"))
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("profileForm", samePropertyValuesAs(profileForm)));
    }





}
