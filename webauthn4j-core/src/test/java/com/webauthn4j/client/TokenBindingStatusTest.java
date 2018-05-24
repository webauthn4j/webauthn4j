package com.webauthn4j.client;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenBindingStatusTest {

    @Test(expected = IllegalArgumentException.class)
    public void create_with_illegal_value_test(){
        TokenBindingStatus.create("illegal");
    }

    @Test
    public void create_test(){
        TokenBindingStatus status = TokenBindingStatus.create("supported");
        assertThat(status).isEqualTo(TokenBindingStatus.SUPPORTED);
    }
}
