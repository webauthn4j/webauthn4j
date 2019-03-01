package com.webauthn4j.request;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

public class PublicKeyCredentialUserEntityTest {

    @Test
    public void constructor_test() {
        PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity(new byte[16], "name", "displayName");
        assertAll(
                () -> assertThat(userEntity.getId()).isEqualTo(new byte[16]),
                () -> assertThat(userEntity.getName()).isEqualTo("name"),
                () -> assertThat(userEntity.getDisplayName()).isEqualTo("displayName"),
                () -> assertThat(userEntity.getIcon()).isEqualTo(null)
        );
    }

    @Test
    public void getter_test() {
        PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity(new byte[16], "name", "displayName", "icon");
        assertAll(
                () -> assertThat(userEntity.getId()).isEqualTo(new byte[16]),
                () -> assertThat(userEntity.getName()).isEqualTo("name"),
                () -> assertThat(userEntity.getDisplayName()).isEqualTo("displayName"),
                () -> assertThat(userEntity.getIcon()).isEqualTo("icon")
        );
    }

    @Test
    public void equals_hashCode_test() {
        PublicKeyCredentialUserEntity instanceA = new PublicKeyCredentialUserEntity(new byte[16], "name", "displayName", "icon");
        PublicKeyCredentialUserEntity instanceB = new PublicKeyCredentialUserEntity(new byte[16], "name", "displayName", "icon");

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}