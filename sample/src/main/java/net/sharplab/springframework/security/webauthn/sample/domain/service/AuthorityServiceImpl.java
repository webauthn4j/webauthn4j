package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.MessageCodes;
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
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.terasoluna.gfw.common.message.ResultMessages;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 権限サービス
 */
@Service
@Transactional
public class AuthorityServiceImpl implements AuthorityService {

    private final UserEntityRepository userEntityRepository;
    private final GroupEntityRepository groupEntityRepository;
    private final AuthorityEntityRepository authorityEntityRepository;

    private final ModelMapper modelMapper;

    @Autowired
    public AuthorityServiceImpl(UserEntityRepository userEntityRepository, GroupEntityRepository groupEntityRepository, AuthorityEntityRepository authorityEntityRepository, ModelMapper modelMapper) {
        this.userEntityRepository = userEntityRepository;
        this.groupEntityRepository = groupEntityRepository;
        this.authorityEntityRepository = authorityEntityRepository;
        this.modelMapper = modelMapper;
    }

    @Override
    public Authority findOne(Integer authorityId) {
        AuthorityEntity retrievedAuthorityEntity = authorityEntityRepository.findOne(authorityId);
        if(retrievedAuthorityEntity == null){
            throw new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND));
        }
        return modelMapper.map(retrievedAuthorityEntity, Authority.class);
    }

    @Override
    @Transactional(readOnly = true)
    public List<Authority> findAll() {
        return modelMapper.map(authorityEntityRepository.findAll(), DomainTypeTokens.AuthorityList);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<Authority> findAll(Pageable pageable) {
        return modelMapper.map(authorityEntityRepository.findAll(pageable), DomainTypeTokens.AuthorityPage);
    }

    @Override
    public Page<Authority> findAllByKeyword(Pageable pageable, String keyword) {
        if(keyword == null){
            return modelMapper.map(authorityEntityRepository.findAll(pageable), DomainTypeTokens.AuthorityPage);
        }
        else {
            return modelMapper.map(authorityEntityRepository.findAllByKeyword(pageable, keyword), DomainTypeTokens.AuthorityPage);
        }

    }

    @Override
    public void update(Authority authority) {
        AuthorityEntity retreivedAuthorityEntity = authorityEntityRepository.findOne(authority.getId());
        if(retreivedAuthorityEntity == null){
            throw new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND));
        }
        modelMapper.map(authority, retreivedAuthorityEntity);
    }

    @Override
    public void update(AuthorityUpdateDto authorityUpdateDto) {
        AuthorityEntity retrievedAuthorityEntity = authorityEntityRepository.findOne(authorityUpdateDto.getId());
        if(retrievedAuthorityEntity == null){
            throw new WebAuthnSampleEntityNotFoundException(ResultMessages.error().add(MessageCodes.Error.Authority.AUTHORITY_NOT_FOUND));
        }
        List<UserEntity> userEntityList = Arrays.stream(authorityUpdateDto.getUsers()).mapToObj(userEntityRepository::findOne).collect(Collectors.toList());
        List<GroupEntity> groupEntityList = Arrays.stream(authorityUpdateDto.getGroups()).mapToObj(groupEntityRepository::findOne).collect(Collectors.toList());
        retrievedAuthorityEntity.setUsers(userEntityList);
        retrievedAuthorityEntity.setGroups(groupEntityList);
    }

    @Override
    public Page<User> findAllCandidateUsersByKeyword(Pageable pageable, String keyword) {
        Page<UserEntity> userEntities;
        if(keyword == null){
            userEntities = userEntityRepository.findAll(pageable);
        }
        else {
            userEntities = userEntityRepository.findAllByKeyword(pageable, keyword);
        }
        return modelMapper.map(userEntities, DomainTypeTokens.UserPage);
    }

    @Override
    public Page<Group> findAllCandidateGroupsByKeyword(Pageable pageable, String keyword) {
        Page<GroupEntity> groupEntities;
        if(keyword == null){
            groupEntities = groupEntityRepository.findAll(pageable);
        }
        else {
            groupEntities = groupEntityRepository.findAllByKeyword(pageable, keyword);
        }
        return modelMapper.map(groupEntities, DomainTypeTokens.GroupPage);
    }


}
