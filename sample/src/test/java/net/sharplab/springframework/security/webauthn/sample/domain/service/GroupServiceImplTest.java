package net.sharplab.springframework.security.webauthn.sample.domain.service;


import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManager;
import net.sharplab.springframework.security.webauthn.sample.domain.config.ModelMapperConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authority;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.GroupEntityRepository;
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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


/**
 * GroupServiceのテスト
 */
public class GroupServiceImplTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @InjectMocks
    private GroupServiceImpl target;

    @Mock
    private GroupEntityRepository groupEntityRepository;

    @SuppressWarnings("unused")
    @Mock
    private UserManager userManager;

    @Mock
    private Pageable pageable;

    @SuppressWarnings("unused")
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
        int groupId = 1;
        GroupEntity retreivedGroupEntity = new GroupEntity();
        retreivedGroupEntity.setId(groupId);

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retreivedGroupEntity);

        //When
        Group result = target.findOne(groupId);

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
     * @throws Exception
     */
    @Test
    public void findAll_test1(){
        int groupId1 = 1;
        int groupId2 = 2;
        GroupEntity retrievedGroupEntity1 = new GroupEntity();
        retrievedGroupEntity1.setId(groupId1);
        GroupEntity retrievedGroupEntity2 = new GroupEntity();
        retrievedGroupEntity2.setId(groupId2);
        List<GroupEntity> retrievedGroupEntities = Arrays.asList(retrievedGroupEntity1, retrievedGroupEntity2);

        //Given
        when(groupEntityRepository.findAll()).thenReturn(retrievedGroupEntities);

        //When
        List<Group> result = target.findAll();

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
     * @throws Exception
     */
    @Test
    public void findAll_test2(){
        int groupId1 = 1;
        int groupId2 = 2;
        GroupEntity retrievedGroupEntity1 = new GroupEntity();
        retrievedGroupEntity1.setId(groupId1);
        GroupEntity retrievedGroupEntity2 = new GroupEntity();
        retrievedGroupEntity2.setId(groupId2);
        Page<GroupEntity> retrievedGroupEntities = new PageImpl<>(Arrays.asList(retrievedGroupEntity1, retrievedGroupEntity2));

        //Given
        when(groupEntityRepository.findAll(pageable)).thenReturn(retrievedGroupEntities);

        //When
        Page<Group> result = target.findAll(pageable);

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
     * @throws Exception
     */
    @Test
    public void findAllByKeyword_test1(){
        String keyword = "keyword";

        GroupEntity retrievedGroup1 = new GroupEntity();
        retrievedGroup1.setId(1);
        GroupEntity retrievedGroup2 = new GroupEntity();
        retrievedGroup2.setId(2);
        List<GroupEntity> retrievedGroupList = Arrays.asList(retrievedGroup1, retrievedGroup2);
        Page<GroupEntity> retrievedGroupEntityPage = new PageImpl<>(retrievedGroupList);

        //Given
        when(groupEntityRepository.findAllByKeyword(pageable, keyword)).thenReturn(retrievedGroupEntityPage);

        //When
        Page<Group> result = target.findAllByKeyword(pageable, keyword);
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);
    }

    /**
     * [前提条件]
     * レポジトリ呼出成功
     * [呼出条件]
     * keywordあり
     * [期待結果]
     * 処理成功
     * @throws Exception
     */
    @Test
    public void findAllByKeyword_test2(){
        String keyword = null;

        GroupEntity retrievedGroup1 = new GroupEntity();
        retrievedGroup1.setId(1);
        GroupEntity retrievedGroup2 = new GroupEntity();
        retrievedGroup2.setId(2);
        List<GroupEntity> retrievedGroupList = Arrays.asList(retrievedGroup1, retrievedGroup2);
        Page<GroupEntity> retrievedGroupEntityPage = new PageImpl<>(retrievedGroupList);

        //Given
        when(groupEntityRepository.findAll(pageable)).thenReturn(retrievedGroupEntityPage);

        //When
        Page<Group> result = target.findAllByKeyword(pageable, keyword);
        assertThat(result).extracting("id", Integer.class).containsExactly(1, 2);
    }

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
    public void create_test1(){
        Group inputGroup = new Group();
        GroupEntity retrievedGroupEntity = new GroupEntity();
        retrievedGroupEntity.setId(1);
        retrievedGroupEntity.setGroupName("groupA");
        //Given
        when(groupEntityRepository.save(any(GroupEntity.class))).thenReturn(retrievedGroupEntity);

        //When
        Group result = target.create(inputGroup);

        //Then
        assertThat(result.getId()).isEqualTo(1);
        assertThat(result.getGroupName()).isEqualTo("groupA");
    }

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
    public void update_test1(){
        int groupId = 1;
        Group inputGroup = new Group();
        inputGroup.setId(groupId);
        inputGroup.setGroupName("groupA");
        User associatedUser = new User();
        associatedUser.setId(2);
        Authority associatedAuthority = new Authority();
        associatedAuthority.setId(3);
        inputGroup.setUsers(Collections.singletonList(associatedUser));
        inputGroup.setAuthorities(Collections.singletonList(associatedAuthority));

        GroupEntity retrievedGroupEntity = new GroupEntity();

        //Given
        when(groupEntityRepository.findOne(groupId)).thenReturn(retrievedGroupEntity);

        //When
        target.update(inputGroup);

        //Then
        assertThat(retrievedGroupEntity.getId()).isEqualTo(groupId);
        assertThat(retrievedGroupEntity.getGroupName()).isEqualTo("groupA");
        assertThat(retrievedGroupEntity.getUsers().get(0).getId()).isEqualTo(2);
        assertThat(retrievedGroupEntity.getAuthorities().get(0).getId()).isEqualTo(3);
    }

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
    public void delete_test1(){
        int groupId = 1;

        //Given
        doNothing().when(groupEntityRepository).delete(groupId);

        //When
        target.delete(groupId);

        //Then
        verify(groupEntityRepository).delete(groupId);
    }

















}
