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

import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPublicKey;

import static org.assertj.core.api.Assertions.assertThat;


class ECUtilTest {

    @Test
    void createUncompressedPublicKey_test(){
        ECPublicKey publicKey = (ECPublicKey)TestAttestationUtil.load2tierTestRootCAPublicKey();
        byte[] uncompressed =  ECUtil.createUncompressedPublicKey(publicKey);
        assertThat(uncompressed).hasSize(65);
        assertThat(uncompressed).isEqualTo(Base64UrlUtil.decode("BM13LrnFulQ14TNByrUKAXrIakbDx5QPf5R2W_nKOOtoLboP5lWJSpgo-sE6dY0XGTkXvOkeVmVGjDNBQITd_yI"));
    }

}
