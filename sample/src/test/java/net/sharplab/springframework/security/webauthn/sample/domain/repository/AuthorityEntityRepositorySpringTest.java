package net.sharplab.springframework.security.webauthn.sample.domain.repository;

import com.github.springtestdbunit.TransactionDbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.AuthorityEntity;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.DbUnitConfig;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureConfig;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;

import javax.transaction.Transactional;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for AuthorityEntityRepository
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@Import({InfrastructureConfig.class, DbUnitConfig.class})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class,
        DirtiesContextTestExecutionListener.class,
        TransactionDbUnitTestExecutionListener.class })
public class AuthorityEntityRepositorySpringTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @Autowired
    private AuthorityEntityRepository target;


    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/AuthorityEntityRepository/setup.xml")
    public void findOneByAuthority_test1(){

        //Given

        //When
        AuthorityEntity authorityEntity = target.findOneByAuthority("ROLE_DUMMY").get();

        //Then
        assertThat(authorityEntity).extracting("authority").containsExactly("ROLE_DUMMY");
    }

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/AuthorityEntityRepository/setup.xml")
    public void findOneByAuthority_test2(){

        //Given

        //When
        AuthorityEntity authorityEntity = target.findOneByAuthority(null).orElse(null);

        //Then
        assertThat(authorityEntity).isNull();
    }


}
