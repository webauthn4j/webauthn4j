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

package integration.component;

import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBDeserializationTest {

    private final JWSFactory jwsFactory = new JWSFactory();

    @Test
    void test_with_mds3_metadata_as_of_202111(){
        JWS<MetadataBLOBPayload> metadataBLOB = jwsFactory.parse(loadBlobAsString("integration/component/blob.jwt"), MetadataBLOBPayload.class);
        assertThat(metadataBLOB).isNotNull();
    }

    @Test
    void test_with_test_data(){
        JWS<MetadataBLOBPayload> metadataBLOB = jwsFactory.parse(loadBlobAsString("integration/component/test-blob.jwt"), MetadataBLOBPayload.class);
        assertThat(metadataBLOB).isNotNull();
    }

    private String loadBlobAsString(String classPath){
        try(InputStream inputStream = MetadataBLOBDeserializationTest.class.getClassLoader().getResourceAsStream(classPath)){
            byte[] data = inputStream.readAllBytes();
            return new String(data, StandardCharsets.UTF_8);
        }catch (IOException e){
            throw new UncheckedIOException(e);
        }
    }

}
