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

package com.webauthn4j.metadata.data.statement;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.UserVerificationMethod;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationMethodDescriptorTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void test(){
        VerificationMethodDescriptor verificationMethodDescriptor = createVerificationMethodDescriptor();
        assertThat(verificationMethodDescriptor).isNotNull();
        assertThat(verificationMethodDescriptor.getUserVerificationMethod()).isEqualTo(UserVerificationMethod.PASSCODE_EXTERNAL);
        CodeAccuracyDescriptor codeAccuracyDescriptor = verificationMethodDescriptor.getCaDesc();
        assertThat(codeAccuracyDescriptor).isNotNull();
        assertThat(codeAccuracyDescriptor.getBase()).isEqualTo(10);
        assertThat(codeAccuracyDescriptor.getMinLength()).isEqualTo(4);
        assertThat(codeAccuracyDescriptor.getMaxRetries()).isNull();
        assertThat(codeAccuracyDescriptor.getBlockSlowdown()).isNull();
        assertThat(verificationMethodDescriptor.getBaDesc()).isNull();
        assertThat(verificationMethodDescriptor.getPaDesc()).isNull();
    }

    @Test
    void hashCode_equals_test(){
        VerificationMethodDescriptor instanceA = createVerificationMethodDescriptor();
        VerificationMethodDescriptor instanceB = createVerificationMethodDescriptor();

        assertThat(instanceA)
                .hasSameHashCodeAs(instanceB)
                .isEqualTo(instanceB);
    }

    private VerificationMethodDescriptor createVerificationMethodDescriptor(){
        String uvmString = "            {\n" +
                "              \"userVerificationMethod\": \"passcode_external\",\n" +
                "              \"caDesc\": {\n" +
                "                \"base\": 10,\n" +
                "                \"minLength\": 4\n" +
                "              }\n" +
                "            }";
        return jsonMapper.readValue(uvmString, VerificationMethodDescriptor.class);
    }

}