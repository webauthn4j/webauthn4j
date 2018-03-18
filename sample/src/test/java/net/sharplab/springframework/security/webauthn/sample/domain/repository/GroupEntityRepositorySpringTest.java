package net.sharplab.springframework.security.webauthn.sample.domain.repository;

import com.github.springtestdbunit.TransactionDbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import net.sharplab.springframework.security.webauthn.sample.domain.entity.GroupEntity;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.DbUnitConfig;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.config.InfrastructureConfig;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;

import javax.transaction.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for GroupRepository
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@Import({InfrastructureConfig.class, DbUnitConfig.class})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class,
        DirtiesContextTestExecutionListener.class,
        TransactionDbUnitTestExecutionListener.class })
public class GroupEntityRepositorySpringTest {
    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @Autowired
    private GroupEntityRepository target;

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/GroupEntityRepository/setup.xml")
    public void findAllByKeyword_test1(){

        //Given

        //When
        Page<GroupEntity> groupEntities = target.findAllByKeyword(Pageable.unpaged(), "red");

        //Then
        assertThat(groupEntities).extracting("groupName").containsExactly("red");
    }

    @Test
    @Transactional
    @DatabaseSetup("/DBFixtures/repository/GroupEntityRepository/setup.xml")
    public void findAllByKeyword_test2(){

        //Given

        //When
        Page<GroupEntity> groupEntities = target.findAllByKeyword(Pageable.unpaged(), null);

        //Then
        assertThat(groupEntities.getSize()).isZero();
    }



}
