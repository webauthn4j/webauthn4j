package net.sharplab.springframework.security.webauthn.sample.domain.repository;

import com.github.springtestdbunit.TransactionDbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import net.sharplab.springframework.security.webauthn.sample.SampleWebApplication;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.DbUnitConfig;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureConfig;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;

import javax.transaction.Transactional;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for UserEntityRepository
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@Import({InfrastructureConfig.class, DbUnitConfig.class})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class,
        DirtiesContextTestExecutionListener.class,
        TransactionDbUnitTestExecutionListener.class })
public class UserEntityRepositorySpringTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @Autowired
    private UserEntityRepository target;


    @Test
    @Transactional
    @DatabaseSetup(value = "/DBFixtures/repository/UserEntityRepository/setup.xml")
    public void findByEmailAddress_test1(){
        UserEntity userEntity = target.findOneByEmailAddress("john.doe@example.com").get();
        assertThat(userEntity).isNotNull();
        assertThat(userEntity.getId()).isEqualTo(1);
        assertThat(userEntity.getFirstName()).isEqualTo("John");
        assertThat(userEntity.getLastName()).isEqualTo("Doe");
        assertThat(userEntity.getEmailAddress()).isEqualTo("john.doe@example.com");
        assertThat(userEntity.isLocked()).isFalse();
        assertThat(userEntity.getAuthorities()).extracting("authority").containsExactly("ROLE_DUMMY");
        assertThat(userEntity.getGroups()).extracting("groupName").containsExactly("red", "blue");
    }

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/UserEntityRepository/setup.xml")
    public void findByEmailAddress_test2(){
        Optional<UserEntity> retrievedUserEntity = target.findOneByEmailAddress("non-exist@example.com");
        assertThat(retrievedUserEntity).isNotPresent();
    }

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/UserEntityRepository/setup.xml")
    public void findAllByKeyword_test1(){

        //Given

        //When
        Page<UserEntity> userEntities = target.findAllByKeyword(Pageable.unpaged(), "john.doe@example.com");

        //Then
        assertThat(userEntities).extracting("emailAddress").containsExactly("john.doe@example.com");
    }

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/UserEntityRepository/setup.xml")
    public void findAllByKeyword_test2(){

        //Given

        //When
        Page<UserEntity> userEntities = target.findAllByKeyword(Pageable.unpaged(), "doe@example.com");

        //Then
        assertThat(userEntities).extracting("emailAddress").containsExactly("john.doe@example.com");
    }

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/UserEntityRepository/setup.xml")
    public void findAllByKeyword_test3(){

        //Given

        //When
        Page<UserEntity> userEntities = target.findAllByKeyword(Pageable.unpaged(), "John");

        //Then
        assertThat(userEntities).extracting("emailAddress").containsExactly("john.doe@example.com");
    }

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/UserEntityRepository/setup.xml")
    public void findAllByKeyword_test4(){

        //Given

        //When
        Page<UserEntity> userEntities = target.findAllByKeyword(Pageable.unpaged(), "Doe");

        //Then
        assertThat(userEntities).extracting("emailAddress").containsExactly("john.doe@example.com");
    }

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/UserEntityRepository/setup.xml")
    public void findAllByKeyword_test5(){

        //Given

        //When
        Page<UserEntity> userEntities = target.findAllByKeyword(Pageable.unpaged(), "example.com");

        //Then
        assertThat(userEntities).extracting("emailAddress").containsExactly("john.doe@example.com", "dummy@example.com");
    }



}
