package net.sharplab.springframework.security.webauthn.sample.domain.component;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
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
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

import java.util.List;

/**
 * {@inheritDoc}
 */
@Component
@Transactional
public class GroupManagerImpl implements GroupManager {

    private final ModelMapper modelMapper;

    private final UserEntityRepository userEntityRepository;
    private final GroupEntityRepository groupEntityRepository;
    private final AuthorityEntityRepository authorityEntityRepository;

    @Autowired
    public GroupManagerImpl(ModelMapper mapper, UserEntityRepository userEntityRepository, GroupEntityRepository groupEntityRepository, AuthorityEntityRepository authorityEntityRepository) {
        this.modelMapper = mapper;
        this.userEntityRepository = userEntityRepository;
        this.groupEntityRepository = groupEntityRepository;
        this.authorityEntityRepository = authorityEntityRepository;
    }


    @Override
    public Group findGroup(int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        return modelMapper.map(groupEntity, Group.class);
    }

    @Override
    public List<Group> findAllGroups() {
        List<GroupEntity> groupEntity = groupEntityRepository.findAll();
        return modelMapper.map(groupEntity, DomainTypeTokens.GroupList);
    }

    @Override
    public List<User> findUsersInGroup(int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        return modelMapper.map(groupEntity.getUsers(), DomainTypeTokens.UserList);
    }

    @Override
    public List<User> findUsersInGroup(String groupName) {
        GroupEntity groupEntity = groupEntityRepository.findOneByGroupName(groupName)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        return modelMapper.map(groupEntity.getUsers(), DomainTypeTokens.UserList);
    }

    @Override
    public Group createGroup(Group group) {
        GroupEntity groupEntity = modelMapper.map(group, GroupEntity.class);
        GroupEntity savedGroupEntity = groupEntityRepository.save(groupEntity);
        modelMapper.map(savedGroupEntity, group);
        return group;
    }

    @Override
    public void deleteGroup(int groupId) {
        groupEntityRepository.deleteById(groupId);
    }

    @Override
    public void renameGroup(int groupId, String newName) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        groupEntity.setGroupName(newName);
    }

    @Override
    public void addUserToGroup(int userId, int groupId) {
        UserEntity userEntity = userEntityRepository.findById(userId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.User.USER_NOT_FOUND)));

        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        groupEntity.getUsers().add(userEntity);
    }

    @Override
    public void removeUserFromGroup(int userId, int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        groupEntity.getUsers().remove(userId);
    }

    @Override
    public List<Authority> findGroupAuthorities(int groupId) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        return modelMapper.map(groupEntity.getAuthorities(), DomainTypeTokens.AuthorityList);
    }

    @Override
    public void addGroupAuthority(int groupId, Authority authority) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        AuthorityEntity authorityEntity = modelMapper.map(authority, AuthorityEntity.class);
        groupEntity.getAuthorities().add(authorityEntity);
    }

    @Override
    public void removeGroupAuthority(int groupId, Authority authority) {
        GroupEntity groupEntity = groupEntityRepository.findById(groupId)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        AuthorityEntity authorityEntity = authorityEntityRepository.findById(authority.getId())
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND)));

        groupEntity.getAuthorities().remove(authorityEntity);
    }

}
