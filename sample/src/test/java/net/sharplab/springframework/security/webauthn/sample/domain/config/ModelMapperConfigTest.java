package net.sharplab.springframework.security.webauthn.sample.domain.config;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.test.FixtureProvider;
import org.junit.Test;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for ModelMapperConfig
 */
public class ModelMapperConfigTest {

    private ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

    @Test
    public void map_UserEntityList2UserList_test1(){
        UserEntity sourceItem1 = new UserEntity();
        sourceItem1.setId(1);
        UserEntity sourceItem2 = new UserEntity();
        sourceItem2.setId(2);
        List<UserEntity> source = Arrays.asList(sourceItem1, sourceItem2);
        List<User> userList = modelMapper.map(source, DomainTypeTokens.UserList);
        assertThat(userList).extracting("id").containsExactly(1,2);
    }

    @Test
    public void map_UserEntityList2UserList_test2(){
        List<UserEntity> source = Collections.singletonList(FixtureProvider.createUserEntity());
        List<User> userList = modelMapper.map(source, DomainTypeTokens.UserList);
        assertThat(userList).extracting("id").containsExactly(1);
    }

    @Test
    public void map_UserEntityPage2UserPage_test1(){
        UserEntity sourceItem0 = new UserEntity();
        sourceItem0.setId(0);
        UserEntity sourceItem1 = new UserEntity();
        sourceItem1.setId(1);
        Page<UserEntity> source = new PageImpl<>(Arrays.asList(sourceItem0, sourceItem1));
        Page<User> userList = modelMapper.map(source, DomainTypeTokens.UserPage);
        assertThat(userList).extracting("id").containsExactly(0,1);
        assertThat(userList.getContent().get(0)).isInstanceOf(User.class);
        assertThat(userList.getContent().get(1)).isInstanceOf(User.class);
    }


}
