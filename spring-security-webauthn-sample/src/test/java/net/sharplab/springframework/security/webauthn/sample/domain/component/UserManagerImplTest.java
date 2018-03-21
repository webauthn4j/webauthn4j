package net.sharplab.springframework.security.webauthn.sample.domain.component;

import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Test for UserDetailsServiceImpl
 */
@SuppressWarnings("unchecked")
public class UserManagerImplTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @InjectMocks
    private UserManagerImpl target;

    @Mock
    private UserEntityRepository userEntityRepository;

    @Spy
    ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

    @Test
    public void findOne_test1(){
        int userId = 1;
        UserEntity retrievedUser = new UserEntity();
        retrievedUser.setId(userId);

        //Given
        when(userEntityRepository.findById(userId)).thenReturn(Optional.of(retrievedUser));

        //When
        User result = target.findById(userId);

        //Then
        assertThat(result.getId()).isEqualTo(1);

    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void findOne_test2(){
        int userId = 1;

        //Given
        when(userEntityRepository.findById(userId)).thenReturn(Optional.empty());

        //When
        User result = target.findById(userId);
    }

    @Test
    public void loadUserByUsername_test1(){

        String emailAddress = "dummy@example.com";
        UserEntity retrievedUser = new UserEntity();
        retrievedUser.setEmailAddress(emailAddress);

        //Given
        when(userEntityRepository.findOneByEmailAddress(emailAddress)).thenReturn(Optional.of(retrievedUser));

        //When
        User user = (User)target.loadUserByUsername(emailAddress);

        //Then
        assertThat(user.getEmailAddress()).isEqualTo(emailAddress);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void loadUserByUsername_test2(){

        String emailAddress = "dummy@example.com";

        //Given
        when(userEntityRepository.findOneByEmailAddress(emailAddress)).thenReturn(Optional.empty());

        //When
        User user = (User)target.loadUserByUsername(emailAddress);
    }


    @Test
    public void create_test1(){
        String emailAddress = "dummy@example.com";
        User sampleUser = new User();
        sampleUser.setEmailAddress(emailAddress);
        UserEntity sampleUserEntity = new UserEntity();
        sampleUserEntity.setId(1);
        sampleUserEntity.setEmailAddress(emailAddress);

        //Given
        when(userEntityRepository.findOneByEmailAddress(emailAddress)).thenReturn(Optional.empty());
        when(userEntityRepository.save(any(UserEntity.class))).thenReturn(sampleUserEntity);

        //When
        User result = target.createUser(sampleUser);

        //Then
        verify(userEntityRepository).save(any(UserEntity.class));
        assertThat(result.getId()).isEqualTo(1);
    }

    @Test(expected = WebAuthnSampleBusinessException.class)
    public void create_test2(){
        String emailAddress = "dummy@example.com";
        User sampleUser = new User();
        sampleUser.setEmailAddress(emailAddress);
        UserEntity sampleUserEntity = new UserEntity();
        sampleUserEntity.setEmailAddress(emailAddress);

        //Given
        when(userEntityRepository.findOneByEmailAddress(emailAddress)).thenReturn(Optional.of(sampleUserEntity));

        //When
        target.createUser(sampleUser);

        //Then
        verify(userEntityRepository, times(0)).save(any(UserEntity.class));
    }

    @Test
    public void update_test1(){
        int userId = 1;
        String emailAddress = "dummy@example.com";
        UserEntity retrievedUserEntity = new UserEntity();
        retrievedUserEntity.setId(userId);
        User inputUser = new User();
        inputUser.setId(userId);
        inputUser.setEmailAddress(emailAddress);

        //Given
        target.modelMapper = new ModelMapper();
        when(userEntityRepository.findById(userId)).thenReturn(Optional.of(retrievedUserEntity));

        //When
        target.updateUser(inputUser);

        //Then
        assertThat(retrievedUserEntity.getEmailAddress()).isEqualTo(emailAddress);

    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void update_test2(){
        int userId = 1;
        String emailAddress = "dummy@example.com";
        User inputUser = new User();
        inputUser.setId(userId);
        inputUser.setEmailAddress(emailAddress);

        //Given
        target.modelMapper = new ModelMapper();
        when(userEntityRepository.findById(userId)).thenReturn(Optional.empty());

        //When
        target.updateUser(inputUser);

        //Then
    }

    @Test
    public void delete_test1(){
        int userId = 1;

        //Given
        when(userEntityRepository.findById(userId)).thenReturn(Optional.of(new UserEntity()));
        doNothing().when(userEntityRepository).deleteById(userId);

        //When
        target.deleteUser(userId);

        //Then
        verify(userEntityRepository).findById(userId);
        verify(userEntityRepository).deleteById(userId);
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void delete_test2(){
        int userId = 1;

        //Given
        when(userEntityRepository.findById(userId)).thenReturn(Optional.empty());

        //When
        target.deleteUser(userId);

        //Then
    }

    @Test
    public void delete_test3(){
        String username = "dummy@example.com";
        int userId = 1;
        UserEntity retrievedUser = new UserEntity();
        retrievedUser.setId(userId);

        //Given
        when(userEntityRepository.findOneByEmailAddress(username)).thenReturn(Optional.of(retrievedUser));
        doNothing().when(userEntityRepository).delete(retrievedUser);

        //When
        target.deleteUser(username);

        //Then
        verify(userEntityRepository).findOneByEmailAddress(username);
        verify(userEntityRepository).delete(retrievedUser);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void delete_test4(){
        String username = "dummy@example.com";
        int userId = 1;
        UserEntity retreivedUser = new UserEntity();
        retreivedUser.setId(userId);

        //Given
        when(userEntityRepository.findOneByEmailAddress(username)).thenReturn(Optional.empty());

        //When
        target.deleteUser(username);

        //Then
    }


    @Test
    public void userExists_test1(){
        String username = "dummy@example.com";
        UserEntity retreivedUser = new UserEntity();

        //Given
        when(userEntityRepository.findOneByEmailAddress(username)).thenReturn(Optional.of(retreivedUser));

        //When
        boolean result = target.userExists(username);

        //Then
        verify(userEntityRepository).findOneByEmailAddress(username);
        assertThat(result).isTrue();
    }

    @Test
    public void userExists_test2(){
        String username = "dummy@example.com";

        //Given
        when(userEntityRepository.findOneByEmailAddress(username)).thenReturn(Optional.empty());

        //When
        boolean result = target.userExists(username);

        //Then
        verify(userEntityRepository).findOneByEmailAddress(username);
        assertThat(result).isFalse();
    }

    @Test
    public void changePassword_test1(){
        String oldPassword = "oldPassword";
        String newPassword = "newPassword";
        User retrievedUser = mock(User.class);


        //Given
        SecurityContextHolder.setContext(createMockSecurityContext(retrievedUser));

        //When
        target.changePassword(oldPassword, newPassword);

        //Then
        verify(retrievedUser).setPassword(newPassword);
    }

    @Test(expected = org.springframework.security.access.AccessDeniedException.class)
    public void changePassword_test2(){
        String oldPassword = "oldPassword";
        String newPassword = "newPassword";

        //Given
        SecurityContextHolder.setContext(createMockSecurityContext(null));

        //When
        target.changePassword(oldPassword, newPassword);
    }



    private SecurityContext createMockSecurityContext(Object principal){
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(principal);
        return securityContext;
    }

}
