package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.domain.exception.WebAuthnSampleEntityNotFoundException;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Group;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.GroupEntityRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

import java.util.List;

/**
 * グループサービス
 */
@Service
@Transactional
public class GroupServiceImpl implements GroupService {

    private final GroupEntityRepository groupEntityRepository;

    private final ModelMapper modelMapper;

    @Autowired
    public GroupServiceImpl(GroupEntityRepository groupEntityRepository, ModelMapper modelMapper) {
        this.groupEntityRepository = groupEntityRepository;
        this.modelMapper = modelMapper;
    }

    @Override
    @Transactional(readOnly = true)
    public Group findOne(int id) {
        GroupEntity retrievedGroupEntity = groupEntityRepository.findById(id)
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));

        return modelMapper.map(retrievedGroupEntity, Group.class);
    }

    @Override
    @Transactional(readOnly = true)
    public List<Group> findAll() {
        return modelMapper.map(groupEntityRepository.findAll(), DomainTypeTokens.GroupList);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Group> findAll(Pageable pageable) {
        return modelMapper.map(groupEntityRepository.findAll(pageable), DomainTypeTokens.GroupPage);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Group> findAllByKeyword(Pageable pageable, String keyword) {
        if (keyword == null) {
            return modelMapper.map(groupEntityRepository.findAll(pageable), DomainTypeTokens.GroupPage);
        } else {
            return modelMapper.map(groupEntityRepository.findAllByKeyword(pageable, keyword), DomainTypeTokens.GroupPage);
        }
    }

    @Override
    public Group create(Group group) {
        GroupEntity groupEntity = modelMapper.map(group, GroupEntity.class);
        GroupEntity savedGroup = groupEntityRepository.save(groupEntity);
        return modelMapper.map(savedGroup, Group.class);
    }

    @Override
    public void update(Group group) {
        GroupEntity retrievedGroupEntity = groupEntityRepository.findById(group.getId())
                .orElseThrow(() -> new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Group.GROUP_NOT_FOUND)));
        modelMapper.map(group, retrievedGroupEntity);
    }

    @Override
    public void delete(int id) {
        groupEntityRepository.deleteById(id);
    }
}
