/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AssertUtilTest {

    @Test
    void notNull_test() {
        Object object = new Object();
        assertThatCode(() -> AssertUtil.notNull(object, "message")).doesNotThrowAnyException();
    }

    @Test
    void notNull_test_with_null() {
        assertThatThrownBy(() -> AssertUtil.notNull(null, "message"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("message");
    }

    @Test
    void notEmpty_test_with_list() {
        assertThatCode(() -> AssertUtil.notEmpty(Collections.singletonList(new Object()), "message")).doesNotThrowAnyException();
    }

    @Test
    void notEmpty_test_with_array() {
        assertThatCode(() -> AssertUtil.notEmpty(Arrays.array(new Object()), "message")).doesNotThrowAnyException();
    }

    @Test
    void notEmpty_test_with_null_as_set() {
        assertThatThrownBy(() -> AssertUtil.notEmpty((Set<?>) null, "message"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("message");
    }

    @Test
    void notEmpty_test_with_null_as_array() {
        assertThatThrownBy(() -> AssertUtil.notEmpty((Object[]) null, "message"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("message");
    }

    @Test
    void notEmpty_test_with_empty_set() {
        assertThatThrownBy(() -> AssertUtil.notEmpty(new HashSet<>(), "message"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("message");
    }

    @Test
    void notEmpty_test_with_empty_array() {
        Object[] value = new Object[0];
        assertThatThrownBy(() -> AssertUtil.notEmpty(value, "message"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("message");
    }

}
