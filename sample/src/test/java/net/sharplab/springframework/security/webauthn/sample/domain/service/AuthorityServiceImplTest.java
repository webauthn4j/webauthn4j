package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.dto.AuthorityUpdateDto;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Test for AuthorityService
 */
public class AuthorityServiceImplTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @InjectMocks
    private AuthorityServiceImpl target;

    @Mock
    private UserEntityRepository userEntityRepository;

    @Mock
    private GroupEntityRepository groupEntityRepository;

    @Mock
    private AuthorityEntityRepository authorityEntityRepository;

    @Mock
    private Pageable pageable;

    @Spy
    private ModelMapper modelMapper = ModelMapperConfig.createModelMapper();

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * 処理成功
     * @throws Exception
     */
    @Test
    public void findOne_test1(){

        int authorityId = 1;
        AuthorityEntity retreivedAuthorityEntity = new AuthorityEntity();
        retreivedAuthorityEntity.setId(authorityId);

        //Given
        when(authorityEntityRepository.findById(authorityId)).thenReturn(Optional.of(retreivedAuthorityEntity));

        //When
        Authority result = target.findOne(authorityId);

        //Then
        assertThat(result.getId()).isEqualTo(1);
    }

    /**
     * [前提条件]
     * レポジトリがnullを返却
     * [呼出条件]
     * 非実在idを指定
     * [期待結果]
     * EntityNotFoundExceptionの発生
     */
    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void findOne_test2(){

        int authorityId = 1;

        //Given
        when(authorityEntityRepository.findById(authorityId)).thenReturn(Optional.empty());

        //When
        Authority result = target.findOne(authorityId);

        //Then
        assertThat(result.getId()).isEqualTo(1);
    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * なし
     * [期待結果]
     * 処理成功
     */
    @Test
    public void findAll_test1(){
        int authorityId1 = 1;
        int authorityId2 = 2;
        AuthorityEntity retrievedAuthorityEntity1 = new AuthorityEntity();
        retrievedAuthorityEntity1.setId(authorityId1);
        AuthorityEntity retrievedAuthorityEntity2 = new AuthorityEntity();
        retrievedAuthorityEntity2.setId(authorityId2);
        List<AuthorityEntity> retrievedAuthorityEntities = Arrays.asList(retrievedAuthorityEntity1, retrievedAuthorityEntity2);

        //Given
        when(authorityEntityRepository.findAll()).thenReturn(retrievedAuthorityEntities);

        //When
        List<Authority> result = target.findAll();

        //Then
        assertThat(result).extracting("id").containsExactly(1, 2);

    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * なし
     * [期待結果]
     * 処理成功
     */
    @Test
    public void findAll_test2(){
        int authorityId1 = 1;
        int authorityId2 = 2;
        AuthorityEntity retrievedAuthorityEntity1 = new AuthorityEntity();
        retrievedAuthorityEntity1.setId(authorityId1);
        AuthorityEntity retrievedAuthorityEntity2 = new AuthorityEntity();
        retrievedAuthorityEntity2.setId(authorityId2);
        Page<AuthorityEntity> retrievedAuthorityEntities = new PageImpl<>(Arrays.asList(retrievedAuthorityEntity1, retrievedAuthorityEntity2));

        //Given
        when(authorityEntityRepository.findAll(pageable)).thenReturn(retrievedAuthorityEntities);

        //When
        Page<Authority> result = target.findAll(pageable);

        //Then
        assertThat(result).extracting("id").containsExactly(1, 2);

    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * keywordあり
     * [期待結果]
     * 処理成功
     */
    @Test
    public void findAllByKeyword_test1(){
        String keyword = "keyword";

        AuthorityEntity retrievedAuthority1 = new AuthorityEntity();
        retrievedAuthority1.setId(1);
        AuthorityEntity retrievedAuthority2 = new AuthorityEntity();
        retrievedAuthority2.setId(2);
        List<AuthorityEntity> retrievedAuthorityList = Arrays.asList(retrievedAuthority1, retrievedAuthority2);
        Page<AuthorityEntity> retrievedAuthorityEntityPage = new PageImpl<>(retrievedAuthorityList);

        //Given
        when(authorityEntityRepository.findAllByKeyword(pageable, keyword)).thenReturn(retrievedAuthorityEntityPage);

        //When
        Page<Authority> result = target.findAllByKeyword(pageable, keyword);
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);
    }


    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * keywordあり
     * [期待結果]
     * 処理成功
     */
    @Test
    public void findAllByKeyword_test2(){
        String keyword = null;

        AuthorityEntity retrievedAuthority1 = new AuthorityEntity();
        retrievedAuthority1.setId(1);
        AuthorityEntity retrievedAuthority2 = new AuthorityEntity();
        retrievedAuthority2.setId(2);
        List<AuthorityEntity> retrievedAuthorityList = Arrays.asList(retrievedAuthority1, retrievedAuthority2);
        Page<AuthorityEntity> retrievedAuthorityEntityPage = new PageImpl<>(retrievedAuthorityList);

        //Given
        when(authorityEntityRepository.findAll(pageable)).thenReturn(retrievedAuthorityEntityPage);

        //When
        Page<Authority> result = target.findAllByKeyword(pageable, keyword);
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);
    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * 処理成功
     */
    @Test
    public void update_test1(){
        int authorityId = 1;
        Authority inputAuthority = new Authority();
        inputAuthority.setId(authorityId);
        inputAuthority.setAuthority("authorityA");
        User associatedUser = new User();
        associatedUser.setId(2);
        Group associatedGroup = new Group();
        associatedGroup.setId(3);
        inputAuthority.setUsers(Collections.singletonList(associatedUser));
        inputAuthority.setGroups(Collections.singletonList(associatedGroup));

        AuthorityEntity retrievedAuthorityEntity = new AuthorityEntity();

        //Given
        when(authorityEntityRepository.findById(authorityId)).thenReturn(Optional.of(retrievedAuthorityEntity));

        //When
        target.update(inputAuthority);

        //Then
        assertThat(retrievedAuthorityEntity.getId()).isEqualTo(authorityId);
        assertThat(retrievedAuthorityEntity.getAuthority()).isEqualTo("authorityA");
        assertThat(retrievedAuthorityEntity.getUsers().get(0).getId()).isEqualTo(2);
        assertThat(retrievedAuthorityEntity.getGroups().get(0).getId()).isEqualTo(3);
    }

    /**
     * [前提条件]
     * レポジトリがnullを返却
     * [呼出条件]
     * 非実在idを指定
     * [期待結果]
     * 処理成功
     */
    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void update_test2(){
        int authorityId = 1;
        Authority inputAuthority = new Authority();
        inputAuthority.setId(authorityId);
        inputAuthority.setAuthority("authorityA");
        User associatedUser = new User();
        associatedUser.setId(2);
        Group associatedGroup = new Group();
        associatedGroup.setId(3);
        inputAuthority.setUsers(Collections.singletonList(associatedUser));
        inputAuthority.setGroups(Collections.singletonList(associatedGroup));

        //Given
        when(authorityEntityRepository.findById(authorityId)).thenReturn(Optional.empty());

        //When
        target.update(inputAuthority);

        //Then
    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * 処理成功
     */
    @Test
    public void update_test3(){
        int authorityId = 1;
        AuthorityUpdateDto inputAuthorityUpdateDto = new AuthorityUpdateDto();
        inputAuthorityUpdateDto.setId(authorityId);
        inputAuthorityUpdateDto.setUsers(Collections.singletonList(2));
        inputAuthorityUpdateDto.setGroups(Collections.singletonList(3));

        UserEntity retrievedUserEntity = new UserEntity();
        retrievedUserEntity.setId(2);
        GroupEntity retrievedGroupEntity = new GroupEntity();
        retrievedGroupEntity.setId(3);
        AuthorityEntity retrievedAuthorityEntity = new AuthorityEntity();
        retrievedAuthorityEntity.setId(1);
        retrievedAuthorityEntity.setAuthority("authorityA");

        //Given
        when(authorityEntityRepository.findById(authorityId)).thenReturn(Optional.of(retrievedAuthorityEntity));
        when(userEntityRepository.findAllById(any())).thenReturn(Collections.singletonList(retrievedUserEntity));
        when(groupEntityRepository.findAllById(any())).thenReturn(Collections.singletonList(retrievedGroupEntity));

        //When
        target.update(inputAuthorityUpdateDto);

        //Then
        assertThat(retrievedAuthorityEntity.getId()).isEqualTo(authorityId);
        assertThat(retrievedAuthorityEntity.getAuthority()).isEqualTo("authorityA");
        assertThat(retrievedAuthorityEntity.getUsers().get(0).getId()).isEqualTo(2);
        assertThat(retrievedAuthorityEntity.getGroups().get(0).getId()).isEqualTo(3);
    }

    /**
     * [前提条件]
     * 権限レポジトリがnullを返却
     * [呼出条件]
     * 非実在idを指定
     * [期待結果]
     * 処理成功
     */
    @Test(expected = WebAuthnSampleEntityNotFoundException.class)
    public void update_test4(){
        int authorityId = 1;
        AuthorityUpdateDto inputAuthorityUpdateDto = new AuthorityUpdateDto();
        inputAuthorityUpdateDto.setId(authorityId);
        inputAuthorityUpdateDto.setUsers(Collections.singletonList(2));
        inputAuthorityUpdateDto.setGroups(Collections.singletonList(3));

        //Given
        when(authorityEntityRepository.findById(authorityId)).thenReturn(Optional.empty());

        //When
        target.update(inputAuthorityUpdateDto);

        //Then
    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * keywordあり
     * [期待結果]
     * 処理成功
     */
    @Test
    public void findAllCandidateUsersByKeyword_test1(){
        UserEntity retrievedUser1 = new UserEntity();
        retrievedUser1.setId(1);
        UserEntity retrievedUser2 = new UserEntity();
        retrievedUser2.setId(2);
        List<UserEntity> retrievedUserList = Arrays.asList(retrievedUser1, retrievedUser2);
        Page<UserEntity> retrievedUsers = new PageImpl<>(retrievedUserList);

        //Given
        when(userEntityRepository.findAllByKeyword(pageable, "keyword")).thenReturn(retrievedUsers);

        //When
        Page<User> result = target.findAllCandidateUsersByKeyword(pageable, "keyword");

        //Then
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);

    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * keywordなし
     * [期待結果]
     * 処理成功
     */
    @Test
    public void findAllCandidateUsersByKeyword_test2(){
        UserEntity retrievedUser1 = new UserEntity();
        retrievedUser1.setId(1);
        UserEntity retrievedUser2 = new UserEntity();
        retrievedUser2.setId(2);
        List<UserEntity> retrievedUserList = Arrays.asList(retrievedUser1, retrievedUser2);
        Page<UserEntity> retrievedUsers = new PageImpl<>(retrievedUserList);

        //Given
        when(userEntityRepository.findAll(pageable)).thenReturn(retrievedUsers);

        //When
        Page<User> result = target.findAllCandidateUsersByKeyword(pageable, null);

        //Then
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);

    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * keywordあり
     * [期待結果]
     * 処理成功
     */
    @Test
    public void findAllCandidateGroupsByKeyword_test1(){
        GroupEntity retrievedGroup1 = new GroupEntity();
        retrievedGroup1.setId(1);
        GroupEntity retrievedGroup2 = new GroupEntity();
        retrievedGroup2.setId(2);
        List<GroupEntity> retrievedGroupList = Arrays.asList(retrievedGroup1, retrievedGroup2);
        Page<GroupEntity> retrievedGroups = new PageImpl<>(retrievedGroupList);

        //Given
        when(groupEntityRepository.findAllByKeyword(pageable, "keyword")).thenReturn(retrievedGroups);

        //When
        Page<Group> result = target.findAllCandidateGroupsByKeyword(pageable, "keyword");

        //Then
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);

    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * keywordなし
     * [期待結果]
     * 処理成功
     */
    @Test
    public void findAllCandidateGroupsByKeyword_test2(){
        GroupEntity retrievedGroup1 = new GroupEntity();
        retrievedGroup1.setId(1);
        GroupEntity retrievedGroup2 = new GroupEntity();
        retrievedGroup2.setId(2);
        List<GroupEntity> retrievedGroupList = Arrays.asList(retrievedGroup1, retrievedGroup2);
        Page<GroupEntity> retrievedGroups = new PageImpl<>(retrievedGroupList);

        //Given
        when(groupEntityRepository.findAll(pageable)).thenReturn(retrievedGroups);

        //When
        Page<Group> result = target.findAllCandidateGroupsByKeyword(pageable, null);

        //Then
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);

    }
}
