package com.webauthn4j.request;


import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class PublicKeyCredentialRpEntityTest {

    @Test
    public void constructor_test(){
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("localhost", "name");
        assertThat(rpEntity.getId()).isEqualTo("localhost");
        assertThat(rpEntity.getName()).isEqualTo("name");
        assertThat(rpEntity.getIcon()).isEqualTo(null);
    }

    @Test
    public void single_arg_constructor_test(){
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("name");
        assertThat(rpEntity.getId()).isEqualTo(null);
        assertThat(rpEntity.getName()).isEqualTo("name");
        assertThat(rpEntity.getIcon()).isEqualTo(null);
    }

    @Test
    public void getter_test(){
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("localhost", "name", "icon");
        assertThat(rpEntity.getId()).isEqualTo("localhost");
        assertThat(rpEntity.getName()).isEqualTo("name");
        assertThat(rpEntity.getIcon()).isEqualTo("icon");
    }


    @Test
    public void equals_hashCode_test(){
        PublicKeyCredentialRpEntity instanceA = new PublicKeyCredentialRpEntity("localhost", "name", "icon");
        PublicKeyCredentialRpEntity instanceB = new PublicKeyCredentialRpEntity("localhost", "name", "icon");

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }

}