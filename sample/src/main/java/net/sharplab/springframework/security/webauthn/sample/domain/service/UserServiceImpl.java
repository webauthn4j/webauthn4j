package net.sharplab.springframework.security.webauthn.sample.domain.service;

import net.sharplab.springframework.security.webauthn.sample.domain.component.UserManager;
import net.sharplab.springframework.security.webauthn.sample.domain.constant.DomainTypeTokens;
import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * ユーザーサービス
 */
@Service
@Transactional
public class UserServiceImpl implements UserService{

    private final UserEntityRepository userEntityRepository;
    private final UserManager userManager;
    private final ModelMapper modelMapper;

    @Autowired
    public UserServiceImpl(UserEntityRepository userEntityRepository, UserManager userManager, ModelMapper modelMapper) {
        this.userEntityRepository = userEntityRepository;
        this.userManager = userManager;
        this.modelMapper = modelMapper;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional(readOnly = true)
    public User findOne(int id){
        return userManager.findById(id);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional(readOnly = true)
    public List<User> findAll(){
        return modelMapper.map(userEntityRepository.findAll(), DomainTypeTokens.UserList);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional(readOnly = true)
    public Page<User> findAll(Pageable pageable){
        return  modelMapper.map(userEntityRepository.findAll(pageable), DomainTypeTokens.UserPage);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional(readOnly = true)
    public Page<User> findAllByKeyword(Pageable pageable, String keyword) {
        if(keyword == null){
            return modelMapper.map(userEntityRepository.findAll(pageable), DomainTypeTokens.UserPage);
        }
        else {
            return modelMapper.map(userEntityRepository.findAllByKeyword(pageable, keyword), DomainTypeTokens.UserPage);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public User create(User user) {
        return userManager.createUser(user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void update(User user) {
        userManager.updateUser(user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void delete(int id){
        userManager.deleteUser(id);
    }
}
