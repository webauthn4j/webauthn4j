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
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import com.webauthn4j.response.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class AttestationStatementDeserializerTest {

    private ObjectMapper jsonMapper = new Registry().getJsonMapper();

    @Test
    public void test() throws IOException {
        AttestationStatement source = TestUtil.createFIDOU2FAttestationStatement();
        String str = jsonMapper.writeValueAsString(source);
        AttestationStatement obj = jsonMapper.readValue(str, AttestationStatement.class);

        assertThat(obj).isInstanceOf(FIDOU2FAttestationStatement.class);
        assertThat(obj).isEqualTo(source);
    }
}
