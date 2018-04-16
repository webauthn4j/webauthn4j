package com.webauthn4j.util;

import org.assertj.core.util.Arrays;
import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

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

    @Test
    public void notEmpty_test_with_list(){
        AssertUtil.notEmpty(Collections.singletonList(new Object()), "message");
    }

    @Test
    public void notEmpty_test_with_array(){
        AssertUtil.notEmpty(Arrays.array(new Object()), "message");
    }

    @Test
    public void notEmpty_test_with_null_as_set(){
        assertThatThrownBy(()-> AssertUtil.notEmpty((Set)null, "message")).isInstanceOf(IllegalArgumentException.class).hasMessage("message");
    }

    @Test
    public void notEmpty_test_with_null_as_array(){
        assertThatThrownBy(()-> AssertUtil.notEmpty((Object[]) null, "message")).isInstanceOf(IllegalArgumentException.class).hasMessage("message");
    }

    @Test
    public void notEmpty_test_with_empty_set(){
        assertThatThrownBy(()-> AssertUtil.notEmpty(new HashSet<>(), "message")).isInstanceOf(IllegalArgumentException.class).hasMessage("message");
    }

    @Test
    public void notEmpty_test_with_empty_array(){
        assertThatThrownBy(()-> AssertUtil.notEmpty(new Object[0], "message")).isInstanceOf(IllegalArgumentException.class).hasMessage("message");
    }
}
