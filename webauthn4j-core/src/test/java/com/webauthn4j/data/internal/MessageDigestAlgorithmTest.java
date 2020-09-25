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

package com.webauthn4j.data.internal;

import com.webauthn4j.data.MessageDigestAlgorithm;
import com.webauthn4j.util.MessageDigestUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MessageDigestAlgorithmTest {

    @Test
    void getJcaName_test(){
        MessageDigestAlgorithm target = MessageDigestAlgorithm.SHA1;
        assertThat(target.getJcaName()).isEqualTo("SHA-1");
    }

    @Test
    void createMessageDigestObject_test(){
        MessageDigestAlgorithm target = MessageDigestAlgorithm.SHA256;
        assertThat(target.createMessageDigestObject().getAlgorithm()).isEqualTo(MessageDigestUtil.createSHA256().getAlgorithm());
    }

    @Test
    void equals_hashCode_test(){
        assertThat(MessageDigestAlgorithm.create("SHA-256")).isEqualTo(MessageDigestAlgorithm.create("SHA-256"));
        assertThat(MessageDigestAlgorithm.create("SHA-256")).hasSameHashCodeAs(MessageDigestAlgorithm.create("SHA-256"));
    }

}