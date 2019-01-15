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

import org.junit.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

public class KeyUtilTest {

    @Test
    public void createKeyPair_test() {
        KeyPair keyPair = KeyUtil.createECKeyPair();
        assertThat(keyPair).isNotNull();
    }

    @Test
    public void createKeyPair_test_with_seed() throws NoSuchAlgorithmException {
        byte[] seed = new byte[]{0x01, 0x23, 0x45};
        KeyPair keyPairA = KeyUtil.createECKeyPair(seed);
        KeyPair keyPairB = KeyUtil.createECKeyPair(seed);
        assertThat(keyPairA.getPrivate().getEncoded()).isEqualTo(keyPairB.getPrivate().getEncoded());
    }
}
