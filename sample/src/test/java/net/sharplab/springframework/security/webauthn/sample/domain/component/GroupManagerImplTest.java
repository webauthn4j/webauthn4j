package net.sharplab.springframework.security.webauthn.sample.domain.component;


import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authority;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthorityEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.GroupEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.modelmapper.ModelMapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * GroupManagerImplのテスト
 */
@SuppressWarnings("unchecked")
public class GroupManagerImplTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @InjectMocks
    private GroupManagerImpl target;

    @Mock
    private UserEntityRepository userEntityRepository;

    @Mock
    private GroupEntityRepository groupEntityRepository;

    @Mock
    private AuthorityEntityRepository authorityEntityRepository;

    @Spy
    ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

    @Test
    public void findGroup_test1(){
        //Input
        int groupId = 1;
        GroupEntity retreivedGroup = new GroupEntity();
        retreivedGroup.setId(1);

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retreivedGroup);

        //When
        Group result = target.findGroup(groupId);

        //Then
        assertThat(result.getId()).isEqualTo(groupId);
    }

    @Test
    public void findAllGroups_test1(){

        List<GroupEntity> retreivedGroupEntities = Collections.emptyList();

        //Given
        when(groupEntityRepository.findAll()).thenReturn(retreivedGroupEntities);

        //When
        List<Group> result = target.findAllGroups();

        //Then
        assertThat(result).isEqualTo(retreivedGroupEntities);
    }

    @Test
    public void findUsersInGroup_test1(){

        int groupId = 1;
        List<UserEntity> users = Collections.emptyList();
        GroupEntity retreivedGroupEntity = new GroupEntity();
        retreivedGroupEntity.setUsers(users);

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retreivedGroupEntity);

        //When
        List<User> result = target.findUsersInGroup(groupId);

        //Then
        assertThat(result).isEqualTo(users);
    }

    @Test
    public void findUsersInGroup_test2(){

        String groupName = "groupA";
        List<UserEntity> users = Collections.emptyList();
        GroupEntity retreivedGroup = new GroupEntity();
        retreivedGroup.setUsers(users);

        //Given
        when(groupEntityRepository.findOneByGroupName(groupName)).thenReturn(retreivedGroup);

        //When
        List<User> result = target.findUsersInGroup(groupName);

        //Then
        assertThat(result).isEqualTo(users);
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void findUsersInGroup_test3(){

        int groupId = 1;

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(null);

        //When
        target.findUsersInGroup(groupId);
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void findUsersInGroup_test4(){

        String groupName = "groupA";

        //Given
        when(groupEntityRepository.findOneByGroupName(groupName)).thenReturn(null);

        //When
        target.findUsersInGroup(groupName);
    }

    @Test
    public void createGroup_test1(){

        GroupEntity savedGroupEntity = new GroupEntity();
        savedGroupEntity.setId(1);
        Group group = new Group();

        //Given
        when(groupEntityRepository.save(any(GroupEntity.class))).thenReturn(savedGroupEntity);

        //When
        Group result = target.createGroup(group);
        assertThat(result.getId()).isEqualTo(1);
    }

    @Test
    public void deleteGroup_test1(){

        int groupId = 1;

        //Given
        doNothing().when(groupEntityRepository).delete(groupId);

        //When
        target.deleteGroup(groupId);
    }

    @Test
    public void renameGroup_test1(){
        int groupId = 1;
        GroupEntity retreivedGroupEntity = mock(GroupEntity.class);

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retreivedGroupEntity);

        //When
        target.renameGroup(groupId, "newName");

        //Then
        verify(retreivedGroupEntity).setGroupName("newName");
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void renameGroup_test2(){
        int groupId = 1;

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(null);

        //When
        target.renameGroup(groupId, "newName");

    }

    @Test
    public void addUserToGroup_test1(){
        int userId = 1;
        int groupId = 1;

        UserEntity retreivedUser = new UserEntity();
        GroupEntity retreivedGroup = mock(GroupEntity.class);
        List<UserEntity> userList = mock(List.class);

        //Given
        when(userEntityRepository.findOne(userId)).thenReturn(retreivedUser);
        when(groupEntityRepository.findOne(groupId)).thenReturn(retreivedGroup);
        when(retreivedGroup.getUsers()).thenReturn(userList);

        //When
        target.addUserToGroup(userId, groupId);

        //Then
        verify(userList).add(retreivedUser);

    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void addUserToGroup_test2(){
        int userId = 1;
        int groupId = 1;

        GroupEntity retreivedGroup = mock(GroupEntity.class);

        //Given
        when(userEntityRepository.findOne(userId)).thenReturn(null);
        when(groupEntityRepository.findOne(groupId)).thenReturn(retreivedGroup);

        //When
        target.addUserToGroup(userId, groupId);
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void addUserToGroup_test3(){
        int userId = 1;
        int groupId = 1;

        UserEntity retreivedUser = new UserEntity();

        //Given
        when(userEntityRepository.findOne(userId)).thenReturn(retreivedUser);
        when(groupEntityRepository.findOne(groupId)).thenReturn(null);

        //When
        target.addUserToGroup(userId, groupId);
    }

    @Test
    public void removeUserFromGroup_test1(){
        int userId = 1;
        int groupId = 1;
        GroupEntity retreivedGroup = mock(GroupEntity.class);
        List<UserEntity> userList = mock(List.class);

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retreivedGroup);
        when(retreivedGroup.getUsers()).thenReturn(userList);

        //When
        target.removeUserFromGroup(userId, groupId);

        //Then
        verify(userList).remove(groupId);
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void removeUserFromGroup_test2(){
        int userId = 1;
        int groupId = 1;

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(null);

        //When
        target.removeUserFromGroup(userId, groupId);
    }

    @Test
    public void findGroupAuthorities_test1(){
        int groupId = 1;
        GroupEntity retrievedGroup = new GroupEntity();
        AuthorityEntity authorityEntity = new AuthorityEntity();
        authorityEntity.setAuthority("ROLE_ADMIN");
        List<AuthorityEntity> retrievedGroupAuthorities = Collections.singletonList(authorityEntity);
        retrievedGroup.setAuthorities(retrievedGroupAuthorities);

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retrievedGroup);

        //When
        List<Authority> result = target.findGroupAuthorities(groupId);

        //Then
        assertThat(result.get(0).getAuthority()).isSameAs("ROLE_ADMIN");
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void findGroupAuthorities_test2(){
        int groupId = 1;

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(null);

        //When
        target.findGroupAuthorities(groupId);
    }

    @Test
    public void addGroupAuthority_test1(){
        int groupId = 1;
        GroupEntity retrievedGroup = mock(GroupEntity.class);
        List<AuthorityEntity> retrievedGroupAuthorities = mock(List.class);
        AuthorityEntity retrievedGroupAuthority = new AuthorityEntity();

        Authority groupAuthority = new Authority();

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retrievedGroup);
        when(retrievedGroup.getAuthorities()).thenReturn(retrievedGroupAuthorities);
        when(retrievedGroupAuthorities.add(retrievedGroupAuthority)).thenReturn(true);

        //When
        target.addGroupAuthority(groupId, groupAuthority);

        //Then
        verify(retrievedGroup).getAuthorities();
        verify(retrievedGroupAuthorities).add(any(AuthorityEntity.class));
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void addGroupAuthority_test2(){
        int groupId = 1;
        Authority groupAuthority = new Authority();

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(null);

        //When
        target.addGroupAuthority(groupId, groupAuthority);

        //Then
    }

    @Test
    public void removeGroupAuthority_test1(){
        int groupId = 1;
        int authorityId = 2;
        GroupEntity retrievedGroup = new GroupEntity();
        List<AuthorityEntity> retrievedAuthorities = new ArrayList<>();
        AuthorityEntity retrievedAuthorityEntity = new AuthorityEntity();
        retrievedGroup.setAuthorities(retrievedAuthorities);
        retrievedAuthorities.add(retrievedAuthorityEntity);
        retrievedAuthorityEntity.setId(authorityId);

        Authority groupAuthority = new Authority();
        groupAuthority.setId(authorityId);

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retrievedGroup);
        when(authorityEntityRepository.findOne(authorityId)).thenReturn(retrievedAuthorityEntity);

        //When
        target.removeGroupAuthority(groupId, groupAuthority);

        //Then
        assertThat(retrievedAuthorities).doesNotContain(retrievedAuthorityEntity);
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void removeGroupAuthority_test2(){
        int groupId = 1;
        int authorityId = 2;
        Authority groupAuthority = new Authority();

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(null);
        when(authorityEntityRepository.findOne(authorityId)).thenReturn(null);

        //When
        target.removeGroupAuthority(groupId, groupAuthority);

        //Then
    }

    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void removeGroupAuthority_test3(){
        int groupId = 1;
        int authorityId = 2;
        GroupEntity retrievedGroup = mock(GroupEntity.class);
        AuthorityEntity retrievedAuthorityEntity = new AuthorityEntity();
        retrievedAuthorityEntity.setId(authorityId);
        List<AuthorityEntity> retrievedGroupAuthorities = new ArrayList<>();
        retrievedGroupAuthorities.add(retrievedAuthorityEntity);
        Authority groupAuthority = new Authority();
        groupAuthority.setId(1);

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retrievedGroup);
        when(authorityEntityRepository.findOne(authorityId)).thenReturn(null);

        //When
        target.removeGroupAuthority(groupId, groupAuthority);

        //Then
    }

}
