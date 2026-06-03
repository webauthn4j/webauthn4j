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

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;

class StatusReportTest {

    private final JsonMapper jsonMapper = new ObjectConverter().rebuildWithJSONModule(new WebAuthnMetadataJSONModule()).getJsonMapper();

    @Test
    void getter_test(){
        StatusReport target = createStatusReport();
        assertThat(target.getStatus()).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L1);
        assertThat(target.getEffectiveDate()).isEqualTo("2020-11-19");
        assertThat(target.getAuthenticatorVersion()).isEqualTo(2L);
        assertThat(target.getCertificate()).isNotNull();
        assertThat(target.getBatchCertificate()).isNotNull();
        assertThat(target.getUrl()).isEqualTo("https://example.com/update");
        assertThat(target.getCertificationDescriptor()).isEqualTo("FIDO Alliance Sample FIDO2 Authenticator");
        assertThat(target.getCertificateNumber()).isEqualTo("FIDO2100020151221001");
        assertThat(target.getCertificationPolicyVersion()).isEqualTo("1.0.1");
        assertThat(target.getCertificationProfiles()).containsExactly(new CertificationProfile("enterprise"));
        assertThat(target.getCertificationRequirementsVersion()).isEqualTo("1.0.1");
        assertThat(target.getSunsetDate()).isEqualTo("2030-01-01");
        assertThat(target.getFipsRevision()).isEqualTo(3L);
        assertThat(target.getFipsPhysicalSecurityLevel()).isEqualTo(1L);
    }

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_constructor_test(){
        StatusReport target = new StatusReport(
                AuthenticatorStatus.FIDO_CERTIFIED, null, null, null,
                null, null, null, null);
        assertThat(target.getStatus()).isEqualTo(AuthenticatorStatus.FIDO_CERTIFIED);
        assertThat(target.getAuthenticatorVersion()).isNull();
        assertThat(target.getBatchCertificate()).isNull();
        assertThat(target.getCertificationProfiles()).isNull();
        assertThat(target.getSunsetDate()).isNull();
        assertThat(target.getFipsRevision()).isNull();
        assertThat(target.getFipsPhysicalSecurityLevel()).isNull();
    }

    @Test
    void hashCode_equals_test(){
        StatusReport instanceA = createStatusReport();
        StatusReport instanceB = createStatusReport();

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    void equals_with_different_values_test(){
        StatusReport base = createStatusReport();
        assertThat(base).isNotEqualTo(null);
        assertThat(base).isNotEqualTo("string");
        assertThat(base).isEqualTo(base);

        String template = "{\n" +
                "  \"status\": \"%s\",\n" +
                "  \"effectiveDate\": \"%s\",\n" +
                "  \"authenticatorVersion\": %d,\n" +
                "  \"certificate\": \"%s\",\n" +
                "  \"batchCertificate\": \"%s\",\n" +
                "  \"url\": \"%s\",\n" +
                "  \"certificationDescriptor\": \"%s\",\n" +
                "  \"certificateNumber\": \"%s\",\n" +
                "  \"certificationPolicyVersion\": \"%s\",\n" +
                "  \"certificationProfiles\": [\"%s\"],\n" +
                "  \"certificationRequirementsVersion\": \"%s\",\n" +
                "  \"sunsetDate\": \"%s\",\n" +
                "  \"fipsRevision\": %d,\n" +
                "  \"fipsPhysicalSecurityLevel\": %d\n" +
                "}";
        String baseJson = String.format(template,
                "FIDO_CERTIFIED_L1", "2020-11-19", 2, TEST_CERTIFICATE, TEST_CERTIFICATE,
                "https://example.com/update", "FIDO Alliance Sample FIDO2 Authenticator",
                "FIDO2100020151221001", "1.0.1", "enterprise", "1.0.1", "2030-01-01", 3, 1);

        assertThat(base).isEqualTo(jsonMapper.readValue(baseJson, StatusReport.class));

        // Differ by each field
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("FIDO_CERTIFIED_L1", "NOT_FIDO_CERTIFIED"), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("2020-11-19", "2021-01-01"), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("\"authenticatorVersion\": 2", "\"authenticatorVersion\": 99"), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("\"url\": \"https://example.com/update\"", "\"url\": \"https://example.com/other\""), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("\"certificationDescriptor\": \"FIDO Alliance Sample FIDO2 Authenticator\"", "\"certificationDescriptor\": \"Other\""), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("FIDO2100020151221001", "OTHER"), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("\"certificationPolicyVersion\": \"1.0.1\"", "\"certificationPolicyVersion\": \"2.0.0\""), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("enterprise", "consumer"), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("\"certificationRequirementsVersion\": \"1.0.1\"", "\"certificationRequirementsVersion\": \"2.0.0\""), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("2030-01-01", "2031-01-01"), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("\"fipsRevision\": 3", "\"fipsRevision\": 99"), StatusReport.class));
        assertThat(base).isNotEqualTo(jsonMapper.readValue(baseJson.replace("\"fipsPhysicalSecurityLevel\": 1", "\"fipsPhysicalSecurityLevel\": 99"), StatusReport.class));
    }

    private static final String TEST_CERTIFICATE =
            "MIICPTCCAeOgAwIBAgIJAOuexvU3Oy2wMAoGCCqGSM49BAMCMHsxIDAeBgNVBAMMF1" +
            "NhbXBsZSBBdHRlc3RhdGlvbiBSb290MRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMREw" +
            "DwYDVQQLDAhVQUYgVFdHLDESMBAGA1UEBwwJUGFsbyBBbHRvMQswCQYDVQQIDAJDQT" +
            "ELMAkGA1UEBhMCVVMwHhcNMTQwNjE4MTMzMzMyWhcNNDExMTAzMTMzMzMyWjB7MSAw" +
            "HgYDVQQDDBdTYW1wbGUgQXR0ZXN0YXRpb24gUm9vdDEWMBQGA1UECgwNRklETyBBbG" +
            "xpYW5jZTERMA8GA1UECwwIVUFGIFRXRywxEjAQBgNVBAcMCVBhbG8gQWx0bzELMAkG" +
            "A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH8" +
            "hv2D0HXa59/BmpQ7RZehL/FMGzFd1QBg9vAUpOZ3ajnuQ94PR7aMzH33nUSBr8fHYD" +
            "rqOBb58pxGqHJRyX/6NQME4wHQYDVR0OBBYEFPoHA3CLhxFbC0It7zE4w8hk5EJ/MB" +
            "8GA1UdIwQYMBaAFPoHA3CLhxFbC0It7zE4w8hk5EJ/MAwGA1UdEwQFMAMBAf8wCgYI" +
            "KoZIzj0EAwIDSAAwRQIhAJ06QSXt9ihIbEKYKIjsPkriVdLIgtfsbDSu7ErJfzr4Ai" +
            "BqoYCZf0+zI55aQeAHjIzA9Xm63rruAxBZ9ps9z2XNlQ==";

    private StatusReport createStatusReport(){
        String statusReportJson = "{\n" +
                "  \"status\": \"FIDO_CERTIFIED_L1\",\n" +
                "  \"effectiveDate\": \"2020-11-19\",\n" +
                "  \"authenticatorVersion\": 2,\n" +
                "  \"certificate\": \"" + TEST_CERTIFICATE + "\",\n" +
                "  \"batchCertificate\": \"" + TEST_CERTIFICATE + "\",\n" +
                "  \"url\": \"https://example.com/update\",\n" +
                "  \"certificationDescriptor\": \"FIDO Alliance Sample FIDO2 Authenticator\",\n" +
                "  \"certificateNumber\": \"FIDO2100020151221001\",\n" +
                "  \"certificationPolicyVersion\": \"1.0.1\",\n" +
                "  \"certificationProfiles\": [\"enterprise\"],\n" +
                "  \"certificationRequirementsVersion\": \"1.0.1\",\n" +
                "  \"sunsetDate\": \"2030-01-01\",\n" +
                "  \"fipsRevision\": 3,\n" +
                "  \"fipsPhysicalSecurityLevel\": 1\n" +
                "}";
        return jsonMapper.readValue(statusReportJson, StatusReport.class);
    }

}