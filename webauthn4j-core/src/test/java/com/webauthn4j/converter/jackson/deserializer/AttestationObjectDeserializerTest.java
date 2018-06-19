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

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for AttestationObjectDeserializer
 */
public class AttestationObjectDeserializerTest {

    @Test
    public void test() throws IOException {
        ObjectMapper objectMapper = ObjectMapperUtil.createWebAuthnClassesAwareCBORMapper();

        //Given
        String input = "v2hhdXRoRGF0YVi-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBAAAAAQAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv2ExYTFhMQJhMvZhMyZhNPZhNfZiLTEBYi0yWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGItM1ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiLTT2_2dhdHRTdG10v2N4NWOfWQKuMIICqjCCAZKgAwIBAgIQIPdjwEGDsQU32-hQaiJQ7jANBgkqhkiG9w0BAQsFADBKMRIwEAYDVQQKDAlTaGFycExhYi4xNDAyBgNVBAMMK3NwcmluZy1zZWN1cml0eS13ZWJhdXRobiAydGllciB0ZXN0IHJvb3QgQ0EwIBcNMTgwNTAxMTM1MjIwWhgPMjExODA0MDcxMzUyMjBaMGAxDjAMBgNVBAgMBVRva3lvMRIwEAYDVQQKDAlTaGFycExhYi4xOjA4BgNVBAMMMXNwcmluZy1zZWN1cml0eS13ZWJhdXRobiAydGllciB0ZXN0IGF1dGhlbnRpY2F0b3IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARg51usiY4CCNk3ddvy6d8ceEkMg10jKSiW37KkbFyuingrBu6NfbO-hEZm92hD2a76vCMBm3gfdIyxLE-8HzPwoz8wPTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB_wQEAwIHgDAdBgNVHQ4EFgQU0OvOs1pprux0xH27Oy87w6iF2OEwDQYJKoZIhvcNAQELBQADggEBAJlnlTP_FN97p8rcCyS4E1MlEpn_LRDDvAiZxRJO92GZdgqOQTEcgKUh0RibrLdhKZSl_qc-YVagtHiVax21xHxbSo8XvKFtirLf2buktFn7yzx-xEgDwU4dhhvE60gG50Ndsxr7AFU4GN5RlEy6fJexR26StpLaTzmyZGSdwjGjKPUYxYNWOKeBd5lX1eKWDd8vsTUsXYPZFvA-IDFnqsuKwEoBeDFXu8zlWejf3gp7FoPA1z4oFwuPNKBMHZw36jb_vmVlfFAkWDe5MnyDsOjhT5W-yfxQAkxt-889B-qoAs62131JVqBqkEUO9EXeJUJ7LPzPYAy_FDRQ_SSCdyX_Y3NpZ1ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD_Y2ZtdGhmaWRvLXUyZv8";

        //When
        AttestationObject result = objectMapper.readValue(Base64UrlUtil.decode(input), AttestationObject.class);

        //Then
        assertThat(result).isNotNull();
        assertThat(result.getAuthenticatorData()).isNotNull();
        assertThat(result.getFormat()).isEqualTo("fido-u2f");
        assertThat(result.getAttestationStatement()).isNotNull();
        assertThat(result.getAttestationStatement()).isInstanceOf(FIDOU2FAttestationStatement.class);

    }
}
