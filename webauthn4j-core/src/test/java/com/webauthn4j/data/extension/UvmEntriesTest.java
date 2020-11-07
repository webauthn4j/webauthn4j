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

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.data.UserVerificationMethod;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class UvmEntriesTest {

    final JsonConverter jsonConverter = new ObjectConverter().getJsonConverter();

    @Test
    void serialize_test() {
        //noinspection MismatchedQueryAndUpdateOfCollection
        UvmEntry uvmEntry = new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.TEE);
        UvmEntries uvmEntries = new UvmEntries(Collections.singletonList(uvmEntry));

        String json = jsonConverter.writeValueAsString(uvmEntries);
        assertThat(json).isEqualTo("[[2,1,2]]");
    }

    @Test
    void equals_hashCode_test() {
        //noinspection MismatchedQueryAndUpdateOfCollection
        UvmEntry uvmEntry1 = new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.TEE);
        UvmEntries uvmEntries1 = new UvmEntries(Collections.singletonList(uvmEntry1));
        //noinspection MismatchedQueryAndUpdateOfCollection
        UvmEntry uvmEntry2 = new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.TEE);
        UvmEntries uvmEntries2 = new UvmEntries(Collections.singletonList(uvmEntry2));

        assertThat(uvmEntries1)
                .isEqualTo(uvmEntries2)
                .hasSameHashCodeAs(uvmEntries2);
    }

}