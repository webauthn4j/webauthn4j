package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManager;
import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
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
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * ModelMapper設定
 */
@SuppressWarnings("SpringAutowiredFieldsWarningInspection")
@Configuration
@ComponentScan(basePackages = "net.sharplab.springframework.security.webauthn.sample.domain.util.modelmapper.converter")
public class UserServiceImplTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @InjectMocks
    private UserServiceImpl target;

    @Mock
    private UserEntityRepository userEntityRepository;

    @Mock
    private UserManager userManager;

    @Mock
    private Pageable pageable;

    @Spy
    private ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

    @Test
    public void findOne_test1(){

        User retrievedUser = new User();

        //Given
        when(userManager.findById(1)).thenReturn(retrievedUser);

        //When
        User result = target.findOne(1);

        //Then
        assertThat(result).isSameAs(retrievedUser);
    }

    @Test
    public void findAll_test1(){
        UserEntity retrievedUser1 = new UserEntity();
        retrievedUser1.setId(1);
        UserEntity retrievedUser2 = new UserEntity();
        retrievedUser2.setId(2);

        //Given
        when(userEntityRepository.findAll()).thenReturn(Arrays.asList(retrievedUser1, retrievedUser2));

        //When
        List<User> results = target.findAll();

        //Then
        assertThat(results).extracting("id", Integer.class).containsExactly(1, 2);
    }

    @Test
    public void findAll_test2(){
        @SuppressWarnings("unchecked")
        UserEntity retrievedUser1 = new UserEntity();
        retrievedUser1.setId(1);
        UserEntity retrievedUser2 = new UserEntity();
        retrievedUser2.setId(2);
        List<UserEntity> retrievedUserList = Arrays.asList(retrievedUser1, retrievedUser2);
        Page<UserEntity> retrievedUserEntityPage = new PageImpl<>(retrievedUserList);

        //Given
        when(userEntityRepository.findAll(pageable)).thenReturn(retrievedUserEntityPage);

        //When
        Page<User> result = target.findAll(pageable);

        //Then
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);
    }

    @Test
    public void findAllByKeyword_test1(){
        String keyword = "keyword";

        UserEntity retrievedUser1 = new UserEntity();
        retrievedUser1.setId(1);
        UserEntity retrievedUser2 = new UserEntity();
        retrievedUser2.setId(2);
        List<UserEntity> retrievedUserList = Arrays.asList(retrievedUser1, retrievedUser2);
        Page<UserEntity> retrievedUserEntityPage = new PageImpl<>(retrievedUserList);

        //Given
        when(userEntityRepository.findAllByKeyword(pageable, keyword)).thenReturn(retrievedUserEntityPage);

        //When
        Page<User> result = target.findAllByKeyword(pageable, keyword);
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);
    }

    @Test
    public void findAllByKeyword_test2(){
        String keyword = null;

        UserEntity retrievedUser1 = new UserEntity();
        retrievedUser1.setId(1);
        UserEntity retrievedUser2 = new UserEntity();
        retrievedUser2.setId(2);
        List<UserEntity> retrievedUserList = Arrays.asList(retrievedUser1, retrievedUser2);
        Page<UserEntity> retrievedUserEntityPage = new PageImpl<>(retrievedUserList);

        //Given
        when(userEntityRepository.findAll(pageable)).thenReturn(retrievedUserEntityPage);

        //When
        Page<User> result = target.findAllByKeyword(pageable, keyword);
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);
    }


    @Test
    public void create_test1(){
        User inputUser = new User();
        User retreivedUser = new User();
        //Given
        when(userManager.createUser(inputUser)).thenReturn(retreivedUser);

        //When
        User result = target.create(inputUser);

        //Then
        assertThat(result).isSameAs(retreivedUser);
    }

    @Test
    public void update_test1(){
        User inputUser = new User();

        //Given
        doNothing().when(userManager).updateUser(inputUser);

        //When
        target.update(inputUser);

        //Then
        verify(userManager).updateUser(inputUser);
    }

    @Test
    public void delete_test1(){
        int userId = 1;

        //Given
        doNothing().when(userManager).deleteUser(userId);

        //When
        target.delete(userId);

        //Then
        verify(userManager).deleteUser(userId);
    }




}
