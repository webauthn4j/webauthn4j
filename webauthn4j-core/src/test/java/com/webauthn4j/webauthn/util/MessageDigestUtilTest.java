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

package com.webauthn4j.webauthn.util;

import org.junit.Test;

import java.security.MessageDigest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for MessageDigestUtil
 */
public class MessageDigestUtilTest {

    @Test
    public void createMessageDigest_test() {
        MessageDigest s256 = MessageDigestUtil.createMessageDigest("S256");
        MessageDigest s384 = MessageDigestUtil.createMessageDigest("S384");
        MessageDigest s512 = MessageDigestUtil.createMessageDigest("S512");

        MessageDigest sha256 = MessageDigestUtil.createMessageDigest("SHA-256");

        assertThat(s256.getAlgorithm()).isEqualTo("SHA-256");
        assertThat(s384.getAlgorithm()).isEqualTo("SHA-384");
        assertThat(s512.getAlgorithm()).isEqualTo("SHA-512");
        assertThat(sha256.getAlgorithm()).isEqualTo("SHA-256");
    }

    @Test(expected = IllegalArgumentException.class)
    public void createMessageDigest_test_with_wrong_arg() {
        MessageDigest s256 = MessageDigestUtil.createMessageDigest("wrong-arg");
    }

}
