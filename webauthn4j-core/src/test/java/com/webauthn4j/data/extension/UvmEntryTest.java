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

package com.webauthn4j.data.extension;

import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.data.UserVerificationMethod;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class UvmEntryTest {

    @Test
    void constructor_test() {
        UvmEntry target = new UvmEntry(new Number[]{2, 2, 2});
        assertThat(target.getUserVerificationMethod()).isEqualTo(UserVerificationMethod.FINGERPRINT_INTERNAL);
        assertThat(target.getKeyProtectionType()).isEqualTo(KeyProtectionType.HARDWARE);
        assertThat(target.getMatcherProtectionType()).isEqualTo(MatcherProtectionType.TEE);
    }

    @Test
    void getUserVerificationMethod_with_invalid_data_test() {
        UvmEntry target = new UvmEntry(new Number[]{});
        assertThatThrownBy(target::getUserVerificationMethod).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void getKeyProtectionType_with_invalid_data_test() {
        UvmEntry target = new UvmEntry(new Number[]{});
        assertThatThrownBy(target::getKeyProtectionType).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void getMatcherProtectionType_with_invalid_data_test() {
        UvmEntry target = new UvmEntry(new Number[]{});
        assertThatThrownBy(target::getMatcherProtectionType).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void getter_test() {
        //noinspection MismatchedQueryAndUpdateOfCollection
        UvmEntry instance = new UvmEntry(UserVerificationMethod.FINGERPRINT_INTERNAL, KeyProtectionType.HARDWARE, MatcherProtectionType.TEE);

        assertThat(instance.getUserVerificationMethod()).isEqualTo(UserVerificationMethod.FINGERPRINT_INTERNAL);
        assertThat(instance.getKeyProtectionType()).isEqualTo(KeyProtectionType.HARDWARE);
        assertThat(instance.getMatcherProtectionType()).isEqualTo(MatcherProtectionType.TEE);

        assertThat(instance.get(0)).isEqualTo(UserVerificationMethod.FINGERPRINT_INTERNAL.getValue());
        assertThat(instance.get(1)).isEqualTo(KeyProtectionType.HARDWARE.getValue());
        assertThat(instance.get(2)).isEqualTo(MatcherProtectionType.TEE.getValue());

        assertThat(instance.size()).isEqualTo(3);
    }

    @Test
    void equals_hashCode_test() {
        UvmEntry instanceA = new UvmEntry(UserVerificationMethod.FINGERPRINT_INTERNAL, KeyProtectionType.HARDWARE, MatcherProtectionType.TEE);
        UvmEntry instanceB = new UvmEntry(UserVerificationMethod.FINGERPRINT_INTERNAL, KeyProtectionType.HARDWARE, MatcherProtectionType.TEE);

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }


}