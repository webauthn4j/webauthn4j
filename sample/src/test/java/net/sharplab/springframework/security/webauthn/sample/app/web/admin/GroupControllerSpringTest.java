package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import net.sharplab.springframework.security.webauthn.sample.app.config.AppConfig;
import net.sharplab.springframework.security.webauthn.sample.app.config.TestSecurityConfig;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleBusinessException;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.service.GroupService;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureMockConfig;
import org.hamcrest.Matchers;
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
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Test for GroupController
 */
@RunWith(SpringRunner.class)
@WebMvcTest(GroupController.class)
@Import(value = {TestSecurityConfig.class, AppConfig.class, InfrastructureMockConfig.class})
@WithMockUser(roles = "ADMIN")
public class GroupControllerSpringTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    private GroupService groupService;

    /**
     * [前提条件]
     * サービス呼出成功
     * [呼出条件]
     * なし
     * [期待結果]
     * 処理成功
     * @throws Exception
     */
    @Test
    public void list_test1() throws Exception{
        List<Group> groups = Collections.emptyList();
        Page<Group> page = new PageImpl<>(groups);

        //Given
        when(groupService.findAllByKeyword(any(), any())).thenReturn(page);

        //When
        mvc
                .perform(get("/admin/groups/"))
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("groups", instanceOf(List.class)));
    }

    /**
     * [前提条件]
     * なし
     * [呼出条件]
     * なし
     * [期待結果]
     * 処理成功
     * グループフォームの設定
     * @throws Exception
     */
    @Test
    public void template_test1() throws Exception{
        //When
        mvc
                .perform(get("/admin/groups/create"))
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("groupForm", instanceOf(GroupForm.class)));
    }

    /**
     * [前提条件]
     * サービス呼出成功
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * 処理成功
     * リダイレクト
     * 結果メッセージの設定
     * @throws Exception
     */
    @Test
    public void create_test1() throws Exception{
        Group group = new Group();
        group.setId(1);

        //Given
        when(groupService.create(any())).thenReturn(group);

        //When
        mvc.perform(post("/admin/groups/create")
                .with(csrf())
                .param("groupName", "groupA")
        )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/groups/1"))
                .andExpect(flash().attribute("resultMessages", samePropertyValuesAs(ResultMessages.success().add(MessageCodes.Success.Group.GROUP_CREATED))));
    }

    /**
     * [前提条件]
     * なし
     * [呼出条件]
     * 必須パラメータ不足
     * [期待結果]
     * バリデーションエラー
     * @throws Exception
     */
    @Test
    public void create_test2() throws Exception{
        GroupForm expected = new GroupForm();

        //Given

        //When
        mvc.perform(post("/admin/groups/create")
                        .with(csrf())
                //Without required params
        )
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("groupForm", Matchers.samePropertyValuesAs(expected)));
    }

    /**
     * [前提条件]
     * サービス呼出時に業務例外発生
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * HTTP OK
     * サービスが投げた業務例外の結果メッセージの設定
     * @throws Exception
     */
    @Test
    public void create_test3() throws Exception{
        Group group = new Group();
        group.setId(1);

        //Given
        when(groupService.create(any())).thenThrow(new WebAuthnSampleBusinessException(ResultMessages.error().add(MessageCodes.Error.UNKNOWN)));

        //When
        mvc.perform(post("/admin/groups/create")
                .with(csrf())
                .param("groupName", "groupA")
        )
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("groupForm", instanceOf(GroupForm.class)))
                .andExpect(model().attribute("resultMessages", Matchers.samePropertyValuesAs(ResultMessages.error().add(MessageCodes.Error.UNKNOWN))));
    }


    /**
     * [前提条件]
     * なし
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * HTTP OK
     * グループフォームの設定
     * @throws Exception
     */
    @Test
    public void read_test1() throws Exception{
        int groupId = 1;

        Group retrievedGroup = new Group();
        retrievedGroup.setId(groupId);
        retrievedGroup.setGroupName("groupA");
        GroupForm groupForm = new GroupForm();
        groupForm.setGroupName("groupA");

        //Given
        when(groupService.findOne(groupId)).thenReturn(retrievedGroup);

        //When
        mvc
                .perform(get("/admin/groups/1"))
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("groupForm", Matchers.samePropertyValuesAs(groupForm)));
    }

    /**
     * [前提条件]
     * サービス呼出時に業務例外発生
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * HTTP Redirect
     * サービスが投げた業務例外の結果メッセージの設定
     * @throws Exception
     */
    @Test
    public void read_test2() throws Exception{
        int groupId = 1;

        Group retrievedGroup = new Group();
        retrievedGroup.setId(groupId);
        retrievedGroup.setGroupName("groupA");

        //Given
        when(groupService.findOne(groupId)).thenThrow(new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        //When
        mvc
                .perform(get("/admin/groups/1"))
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/groups/"))
                .andExpect(flash().attribute("resultMessages", Matchers.samePropertyValuesAs(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND))));
    }

    /**
     * [前提条件]
     * なし
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * HTTP Redirect
     * 成功結果メッセージの設定
     * @throws Exception
     */
    @Test
    public void update_test1() throws Exception{


        int groupId = 1;

        Group expectedGroup = new Group();
        expectedGroup.setId(groupId);
        expectedGroup.setGroupName("John");

        ArgumentCaptor<Group> captor = ArgumentCaptor.forClass(Group.class);

        //Given
        doNothing().when(groupService).update(captor.capture());

        //When
        mvc
                .perform(post("/admin/groups/1")
                        .with(csrf())
                        .param("groupName", "groupA")
                )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/groups/1"))
                .andExpect(flash().attribute("resultMessages", Matchers.samePropertyValuesAs(ResultMessages.success().add(MessageCodes.Success.Group.GROUP_UPDATED))));


        assertThat(captor.getValue().getId()).isEqualTo(1);
        assertThat(captor.getValue().getGroupName()).isEqualTo("groupA");
    }

    /**
     * [前提条件]
     * なし
     * [呼出条件]
     * 必須パラメータ不足
     * [期待結果]
     * HTTP OK
     * グループフォームの設定
     * @throws Exception
     */
    @Test
    public void update_test2() throws Exception{

        //Given

        //When
        mvc
                .perform(post("/admin/groups/1")
                        .with(csrf())
                )
                //Then
                .andExpect(status().is2xxSuccessful())
                .andExpect(model().attribute("groupForm", hasProperty("groupName", is(nullValue()))));

    }

    /**
     * [前提条件]
     * サービス呼出時に業務例外が発生
     * [呼出条件]
     * 必須パラメータ不足
     * [期待結果]
     * HTTP OK
     * サービスが投げた業務例外の結果メッセージの設定
     * @throws Exception
     */
    @Test
    public void update_test3() throws Exception{


        int groupId = 1;

        Group expectedGroup = new Group();
        expectedGroup.setId(groupId);
        expectedGroup.setGroupName("groupA");

        ArgumentCaptor<Group> captor = ArgumentCaptor.forClass(Group.class);

        //Given
        doThrow(new WebAuthnSampleBusinessException(ResultMessages.error().add(MessageCodes.Error.UNKNOWN))).when(groupService).update(captor.capture());

        //When
        mvc
                .perform(post("/admin/groups/1")
                        .with(csrf())
                        .param("groupName", "groupA")
                )
                //Then
                .andExpect(status().isOk())
                .andExpect(model().attribute("groupForm", hasProperty("groupName", is("groupA"))));


        assertThat(captor.getValue().getId()).isEqualTo(groupId);
        assertThat(captor.getValue().getGroupName()).isEqualTo("groupA");
    }


    /**
     * [前提条件]
     * なし
     * [呼出条件]
     * 必須パラメータ満足
     * [期待結果]
     * HTTP Redirect
     * 成功結果メッセージの設定
     * @throws Exception
     */
    @Test
    public void delete_test1() throws Exception{

        int groupId = 1;

        //Given
        doNothing().when(groupService).delete(groupId);

        //When
        mvc
                .perform(post("/admin/groups/delete/1")
                        .with(csrf())
                )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/groups/"))
                .andExpect(flash().attribute("resultMessages", Matchers.samePropertyValuesAs(ResultMessages.success().add(MessageCodes.Success.Group.GROUP_DELETED))));
    }

    /**
     * [前提条件]
     * なし
     * [呼出条件]
     * 必須パラメータ不足
     * [期待結果]
     * HTTP Redirect
     * サービスが投げた業務例外の結果メッセージの設定
     * @throws Exception
     */
    @Ignore
    @Test
    public void delete_test2() throws Exception{

        //Given

        //When
        mvc
                .perform(post("/admin/groups/delete/ ")
                        .with(csrf())
                )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/groups/"))
                .andExpect(flash().attribute("resultMessages", Matchers.samePropertyValuesAs(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND))));

    }

    /**
     * [前提条件]
     * サービス呼出時に業務例外が発生
     * [呼出条件]
     * 必須パラメータ不足
     * [期待結果]
     * HTTP OK
     * サービスが投げた業務例外の結果メッセージの設定
     * @throws Exception
     */
    @Test
    public void delete_test3() throws Exception{
        int groupId = 1;

        //Given
        doThrow(new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND))).when(groupService).delete(groupId);

        //When
        mvc
                .perform(post("/admin/groups/delete/1")
                        .with(csrf())
                )
                //Then
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/groups/"))
                .andExpect(flash().attribute("resultMessages", Matchers.samePropertyValuesAs(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND))));
    }

}
