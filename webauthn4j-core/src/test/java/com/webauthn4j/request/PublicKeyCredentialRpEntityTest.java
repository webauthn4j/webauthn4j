package com.webauthn4j.request;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class PublicKeyCredentialRpEntityTest {

    @Test
    void constructor_test() {
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("localhost", "name");
        assertAll(
                () -> assertThat(rpEntity.getId()).isEqualTo("localhost"),
                () -> assertThat(rpEntity.getName()).isEqualTo("name"),
                () -> assertThat(rpEntity.getIcon()).isEqualTo(null)
        );
    }

    @Test
    void single_arg_constructor_test() {
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("name");
        assertAll(
                () -> assertThat(rpEntity.getId()).isEqualTo(null),
                () -> assertThat(rpEntity.getName()).isEqualTo("name"),
                () -> assertThat(rpEntity.getIcon()).isEqualTo(null)
        );
    }

    @Test
    void getter_test() {
        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity("localhost", "name", "icon");
        assertAll(
                () -> assertThat(rpEntity.getId()).isEqualTo("localhost"),
                () -> assertThat(rpEntity.getName()).isEqualTo("name"),
                () -> assertThat(rpEntity.getIcon()).isEqualTo("icon")
        );
    }

    @Test
    void equals_hashCode_test() {
        PublicKeyCredentialRpEntity instanceA = new PublicKeyCredentialRpEntity("localhost", "name", "icon");
        PublicKeyCredentialRpEntity instanceB = new PublicKeyCredentialRpEntity("localhost", "name", "icon");

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}