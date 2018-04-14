package com.webauthn4j.util;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AssertUtilTest {

    @Test
    public void notNull_test(){
        Object object = new Object();
        AssertUtil.notNull(object, "message");
    }

    @Test
    public void notNull_test_with_null(){
        assertThatThrownBy(()->{
            AssertUtil.notNull(null, "message");
        }).isInstanceOf(IllegalArgumentException.class).hasMessage("message");
    }
}
