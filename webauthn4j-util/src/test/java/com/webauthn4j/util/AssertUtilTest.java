/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.util;

import org.assertj.core.util.Arrays;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AssertUtilTest {

    @Test
    public void notNull_test() {
        Object object = new Object();
        AssertUtil.notNull(object, "message");
    }

    @Test
    public void notNull_test_with_null() {
        Throwable t = assertThrows(IllegalArgumentException.class,
                () -> AssertUtil.notNull(null, "message")
        );
        assertThat(t).hasMessage("message");
    }

    @Test
    public void notEmpty_test_with_list() {
        AssertUtil.notEmpty(Collections.singletonList(new Object()), "message");
    }

    @Test
    public void notEmpty_test_with_array() {
        AssertUtil.notEmpty(Arrays.array(new Object()), "message");
    }

    @Test
    public void notEmpty_test_with_null_as_set() {
        Throwable t = assertThrows(IllegalArgumentException.class,
                () -> AssertUtil.notEmpty((Set) null, "message")
        );
        assertThat(t).hasMessage("message");
    }

    @Test
    public void notEmpty_test_with_null_as_array() {
        Throwable t = assertThrows(IllegalArgumentException.class,
                () -> AssertUtil.notEmpty((Object[]) null, "message")
        );
        assertThat(t).hasMessage("message");
    }

    @Test
    public void notEmpty_test_with_empty_set() {
        Throwable t = assertThrows(IllegalArgumentException.class,
                () -> AssertUtil.notEmpty(new HashSet<>(), "message")
        );
        assertThat(t).hasMessage("message");
    }

    @Test
    public void notEmpty_test_with_empty_array() {
        Throwable t = assertThrows(IllegalArgumentException.class,
                () -> AssertUtil.notEmpty(new Object[0], "message")
        );
        assertThat(t).hasMessage("message");
    }
}
