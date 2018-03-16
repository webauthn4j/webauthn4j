package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManager;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Test for ProfileService
 */
@SuppressWarnings("WeakerAccess")
public class ProfileServiceImplTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @InjectMocks
    ProfileServiceImpl target;

    @Mock
    UserManager userManager;

    @Test
    public void find_test1(){
        int userId = 2;
        User retreivedUser = new User();
        retreivedUser.setId(userId);

        //Given
        when(userManager.findById(userId)).thenReturn(retreivedUser);

        //When
        User result = target.findOne(userId);

        //Then
        assertThat(result).isSameAs(retreivedUser);

    }

    @Test
    public void update_test1(){
        int userId = 1;
        String emailAddress = "dummy@example.com";
        User inputUser = new User();
        inputUser.setId(userId);
        inputUser.setEmailAddress(emailAddress);

        //Given
        doNothing().when(userManager).updateUser(inputUser);

        //When
        target.update(inputUser);

        //Then
        verify(userManager).updateUser(inputUser);

    }


}
