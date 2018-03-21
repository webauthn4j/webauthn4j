package net.sharplab.springframework.security.webauthn.sample.infrastructure.config;

import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthenticatorEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.AuthorityEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.GroupEntityRepository;
import net.sharplab.springframework.security.webauthn.sample.domain.repository.UserEntityRepository;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Configuration;

/**
 * Created by ynojima on 2017/07/08.
 */
@Configuration
public class JpaMockConfig {

    @MockBean
    public UserEntityRepository userEntityRepository;

    @MockBean
    public GroupEntityRepository groupEntityRepository;

    @MockBean
    public AuthorityEntityRepository authorityEntityRepository;

    @MockBean
    public AuthenticatorEntityRepository authenticatorEntityRepository;

}
