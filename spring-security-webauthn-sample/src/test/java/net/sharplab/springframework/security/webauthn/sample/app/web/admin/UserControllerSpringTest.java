package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.config.AppConfig;
import net.sharplab.springframework.security.webauthn.sample.app.config.TestSecurityConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.service.UserService;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import net.sharplab.springframework.security.webauthn.sample.test.SampleTestUtil;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.terasoluna.gfw.common.message.ResultMessages;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.Is.is;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Test for UserController
 */
@RunWith(SpringRunner.class)
@WebMvcTest(UserController.class)
@Import(value = {TestSecurityConfig.class, AppConfig.class, InfrastructureMockConfig.class})
@WithMockUser(roles = "ADMIN")
public class UserControllerSpringTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    UserService userService;

    @Test
    public void list_test1() throws Exception{
        List<User> users = Collections.emptyList();
        Page<User> page = new PageImpl<>(users);

        //Given
        when(userService.findAllByKeyword(any(), any())).thenReturn(page);

        //When
        mvc
                .perform(get("/admin/users/"))
        //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("users", instanceOf(List.class)));
    }

    @Test
    public void template_test1() throws Exception{
        //When
        mvc
                .perform(get("/admin/users/create"))
        //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("userCreateForm", instanceOf(UserCreateForm.class)));
    }

    @Test
    public void create_test() throws Exception{
        User user = new User();
        user.setId(1);

        //Given
        when(userService.create(any())).thenReturn(user);

        //When
        mvc.perform(post("/admin/users/create")
                .with(csrf())
                .param("userHandle", "TFmvUeeRSQyMUxLDq6x6GA")
                .param("firstName", "John")
                .param("lastName", "Doe")
                .param("emailAddress", "john.doe@example.com")
                .param("rawPassword", "password")
                .param("rawPasswordRetyped", "password")
                .param("locked", "on")
                .param("passwordAuthenticationAllowed", "on")
        )
        //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users/1"))
                .andExpect(flash().attribute("resultMessages", samePropertyValuesAs(ResultMessages.success().add(MessageCodes.Success.User.USER_CREATED))));
    }

    @Test
    public void create_without_required_parameters_test() throws Exception{
        UserCreateForm userCreateForm = new UserCreateForm();
        userCreateForm.setFirstName("John");
        userCreateForm.setLastName("Doe");

        //Given

        //When
        mvc.perform(post("/admin/users/create")
                .with(csrf())
                .param("firstName", "John")
                .param("lastName", "Doe")
                //Without required params
        )
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("userCreateForm", samePropertyValuesAs(userCreateForm)));
    }

    @Test
    public void create_with_exception_from_service_test() throws Exception{
        User user = new User();
        user.setId(1);

        //Given
        when(userService.create(any())).thenThrow(new WebAuthnSampleBusinessException(ResultMessages.error().add(MessageCodes.Error.User.EMAIL_ADDRESS_IS_ALREADY_USED)));

        //When
        mvc.perform(post("/admin/users/create")
                .with(csrf())
                .param("userHandle", "TFmvUeeRSQyMUxLDq6x6GA")
                .param("firstName", "John")
                .param("lastName", "Doe")
                .param("emailAddress", "john.doe@example.com")
                .param("rawPassword", "password")
                .param("rawPasswordRetyped", "password")
                .param("locked", "on")
                .param("passwordAuthenticationAllowed", "on")
        )
        //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("userCreateForm", instanceOf(UserCreateForm.class)))
                .andExpect(model().attribute("resultMessages", samePropertyValuesAs(ResultMessages.error().add(MessageCodes.Error.User.EMAIL_ADDRESS_IS_ALREADY_USED))));
    }

    @Test
    public void read_test() throws Exception{
        int userId = 1;

        User retrievedUser = new User();
        retrievedUser.setId(userId);
        retrievedUser.setFirstName("John");
        retrievedUser.setLastName("Doe");
        retrievedUser.setEmailAddress("john.doe@example.com");
        retrievedUser.setLocked(true);
        retrievedUser.setPasswordAuthenticationAllowed(true);

        UserUpdateForm userUpdateForm = new UserUpdateForm();
        userUpdateForm.setFirstName("John");
        userUpdateForm.setLastName("Doe");
        userUpdateForm.setEmailAddress("john.doe@example.com");
        userUpdateForm.setLocked(true);
        userUpdateForm.setPasswordAuthenticationAllowed(true);

        //Given
        when(userService.findOne(userId)).thenReturn(retrievedUser);

        //When
        mvc
                .perform(get("/admin/users/1"))
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("userUpdateForm", samePropertyValuesAs(userUpdateForm)));
    }

    @Test
    public void read_with_invalid_userId_test() throws Exception{
        int userId = 1;

        User retrievedUser = new User();
        retrievedUser.setId(userId);
        retrievedUser.setFirstName("John");
        retrievedUser.setLastName("Doe");
        retrievedUser.setEmailAddress("john.doe@example.com");
        retrievedUser.setLocked(true);
        retrievedUser.setPasswordAuthenticationAllowed(true);

        //Given
        when(userService.findOne(userId)).thenThrow(new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));

        //When
        mvc
                .perform(get("/admin/users/1"))
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users/"))
                .andExpect(flash().attribute("resultMessages", samePropertyValuesAs(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND))));
    }

    @Test
    public void update_test() throws Exception{


        int userId = 1;

        User exsistingUser = SampleTestUtil.createUser();
        exsistingUser.setId(userId);
        exsistingUser.setLocked(true);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);

        //Given
        when(userService.findOne(userId)).thenReturn(exsistingUser);
        doNothing().when(userService).update(captor.capture());

        //When
        mvc
                .perform(post("/admin/users/1")
                        .with(csrf())
                        .param("firstName", "new first name")
                        .param("lastName", "new last name")
                        .param("emailAddress", "new.email.address@example.com")
                        .param("locked", "on")
                        .param("passwordAuthenticationAllowed", "on")
                )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users/1"))
                .andExpect(flash().attribute("resultMessages", samePropertyValuesAs(ResultMessages.success().add(MessageCodes.Success.User.USER_UPDATED))));


        assertThat(captor.getValue().getId()).isEqualTo(1);
        assertThat(captor.getValue().getFirstName()).isEqualTo("new first name");
        assertThat(captor.getValue().getLastName()).isEqualTo("new last name");
        assertThat(captor.getValue().getEmailAddress()).isEqualTo("new.email.address@example.com");
        assertThat(captor.getValue().getPassword()).isEqualTo(exsistingUser.getPassword());
        assertThat(captor.getValue().isLocked()).isTrue();
        assertThat(captor.getValue().isPasswordAuthenticationAllowed()).isTrue();
    }

    @Test
    public void update_with_insufficient_parameters_test() throws Exception{

        //Given
        when(userService.findOne(anyInt())).thenReturn(SampleTestUtil.createUser());

        //When
        mvc
                .perform(post("/admin/users/1")
                        .with(csrf())
                        .param("firstName", "John")
                        .param("lastName", "Doe")
                )
        //Then
                .andExpect(status().is2xxSuccessful())
                .andExpect(model().attribute("userUpdateForm", hasProperty("firstName", is("John"))))
                .andExpect(model().attribute("userUpdateForm", hasProperty("lastName", is("Doe"))));

    }

    @Test
    public void update_with_exception_from_service_test() throws Exception{


        int userId = 1;

        User existingUser = SampleTestUtil.createUser();
        existingUser.setId(userId);
        existingUser.setLocked(true);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);

        //Given
        when(userService.findOne(userId)).thenReturn(existingUser);
        doThrow(new WebAuthnSampleBusinessException(ResultMessages.error().add(MessageCodes.Error.UNKNOWN))).when(userService).update(captor.capture());

        //When
        mvc
                .perform(post("/admin/users/1")
                        .with(csrf())
                        .param("firstName", "new first name")
                        .param("lastName", "new last name")
                        .param("emailAddress", "new.email.address@example.com")
                        .param("locked", "on")
                        .param("passwordAuthenticationAllowed", "on")
                )
        //Then
        .andExpect(status().isOk())
        .andExpect(model().attribute("userUpdateForm", hasProperty("firstName", is("new first name"))))
        .andExpect(model().attribute("userUpdateForm", hasProperty("lastName", is("new last name"))))
        .andExpect(model().attribute("userUpdateForm", hasProperty("emailAddress", is("new.email.address@example.com"))))
        .andExpect(model().attribute("userUpdateForm", hasProperty("locked", is(true))))
        .andExpect(model().attribute("userUpdateForm", hasProperty("passwordAuthenticationAllowed", is(true))));
    }

    @Test
    public void delete_test() throws Exception{

        int userId = 1;

        //Given
        doNothing().when(userService).delete(userId);

        //When
        mvc
                .perform(post("/admin/users/delete/1")
                        .with(csrf())
                )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users/"))
                .andExpect(flash().attribute("resultMessages", samePropertyValuesAs(ResultMessages.success().add(MessageCodes.Success.User.USER_DELETED))));
    }

    @Ignore
    @Test
    public void delete_without_userId_test() throws Exception{

        //Given

        //When
        mvc
                .perform(post("/admin/users/delete/ ")
                        .with(csrf())
                )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users/"))
                .andExpect(flash().attribute("resultMessages", samePropertyValuesAs(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND))));

    }


    @Test
    public void delete_with_invalid_userId_test() throws Exception{
        int userId = 1;

        //Given
        doThrow(new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND))).when(userService).delete(userId);

        //When
        mvc
                .perform(post("/admin/users/delete/1")
                        .with(csrf())
                )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users/"))
                .andExpect(flash().attribute("resultMessages", samePropertyValuesAs(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND))));
    }

}
