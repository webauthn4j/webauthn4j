/*
 * Copyright 2018 the original author or authors.
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

import java.security.KeyPair;
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

    @Test
    void createKeyPair_test() {
        KeyPair keyPair = ECUtil.createKeyPair();
        assertThat(keyPair).isNotNull();
    }

    @Test
    void createKeyPair_test_with_seed() {
        byte[] seed = new byte[]{0x01, 0x23, 0x45};
        KeyPair keyPairA = ECUtil.createKeyPair(seed);
        KeyPair keyPairB = ECUtil.createKeyPair(seed);
        assertThat(keyPairA.getPrivate().getEncoded()).isEqualTo(keyPairB.getPrivate().getEncoded());
    }

}
