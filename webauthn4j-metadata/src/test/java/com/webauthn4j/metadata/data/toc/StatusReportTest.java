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

package com.webauthn4j.metadata.data.toc;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StatusReportTest {

    private final JsonConverter jsonConverter = new ObjectConverter().getJsonConverter();

    @Test
    void getter_test(){
        StatusReport target = createStatusReport();
        assertThat(target.getStatus()).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L1);
        assertThat(target.getEffectiveDate()).isEqualTo("2020-11-19");
        assertThat(target.getCertificate()).isNull();
        assertThat(target.getUrl()).isNull();
        assertThat(target.getCertificationDescriptor()).isEqualTo("FIDO Alliance Sample FIDO2 Authenticator");
        assertThat(target.getCertificateNumber()).isEqualTo("FIDO2100020151221001");
        assertThat(target.getCertificationPolicyVersion()).isEqualTo("1.0.1");
        assertThat(target.getCertificationRequirementsVersion()).isEqualTo("1.0.1");
    }

    @Test
    void hashCode_equals_test(){
        StatusReport instanceA = createStatusReport();
        StatusReport instanceB = createStatusReport();

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    private StatusReport createStatusReport(){
        String statusReportJson = "{\n" +
                "          \"status\": \"FIDO_CERTIFIED_L1\",\n" +
                "          \"effectiveDate\": \"2020-11-19\",\n" +
                "          \"certificationDescriptor\": \"FIDO Alliance Sample FIDO2 Authenticator\",\n" +
                "          \"certificateNumber\": \"FIDO2100020151221001\",\n" +
                "          \"certificationPolicyVersion\": \"1.0.1\",\n" +
                "          \"certificationRequirementsVersion\": \"1.0.1\"\n" +
                "        }\n";
        return jsonConverter.readValue(statusReportJson, StatusReport.class);
    }

}