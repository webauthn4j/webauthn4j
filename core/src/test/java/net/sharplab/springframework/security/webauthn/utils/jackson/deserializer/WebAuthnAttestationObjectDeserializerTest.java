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

package net.sharplab.springframework.security.webauthn.utils.jackson.deserializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.util.Base64Utils;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for WebAuthnAttestationObjectDeserializer
 */
public class WebAuthnAttestationObjectDeserializerTest {

    @Ignore
    @Test
    public void test() throws IOException {
        ObjectMapper objectMapper = CoreTestUtil.createCBORMapper();

        //Given
        String input = "o2hhdXRoRGF0YVkBLEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACEGtYcgB2I9Pi8jFnIUAoSiwcu_qhHrukfYcbdwM2AXtvtvPsPDt0YV1E0Wo55N0ywXB4BqP-181-H0skABjXUgOEBTA-nPcglfK4PqMNKAH7D5cUE_bUESApv5uOVUKJJTI5F6QtMb9JLd66TwKixWPv5wkzi2faxw6UOhChpg1Mb04o_nn3J8g_GD5l0X7dmbw1dALczYE0dIoxK3Rk_ijY2FsZ2VFUzI1NmF4WCAKdfK3BgGcuTk7CwyGvhWx6FHtulzIf98QyOU4rB8S_WF5WCDej3ykjsl7bHEOfKcRs6Muajo9cb_VfMhDZfbbeo4eWGNmbXRoZmlkby11MmZnYXR0U3RtdKJjeDVjgVkBNTCCATEwgdmgAwIBAgIFAM6vw2EwCgYIKoZIzj0EAwIwITEfMB0GA1UEAxMWRmlyZWZveCBVMkYgU29mdCBUb2tlbjAeFw0xNzA4MTIxMjQxMTBaFw0xNzA4MTQxMjQxMTBaMCExHzAdBgNVBAMTFkZpcmVmb3ggVTJGIFNvZnQgVG9rZW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQeQb9KKCrSufvfw1g5menpgrfyafB5x-V4Vw3kPQkSHHvtVs1oAfbJiPoIOlG8HavcDTBlwfF1zAJc2LtPJrZKMAoGCCqGSM49BAMCA0cAMEQCIGViHaNVsYdmG8z7ZDoNjXAGRaVkpBQXIwFllOYdlFzVAiBQXTTLAqluPuOhamTgMvUt9NlOgCNdbYRA4o3ucSptY2NzaWdYRzBFAiEArPA-6MOP13BdOdlhZIB3UQJFpOQfQrvE_HuSBQBQlnoCIDNeSUap01fzlm3hh8rJQ4Q4rjDiRX6aV8ArLc71VeMJ";

        //When
        WebAuthnAttestationObject result = objectMapper.readValue(Base64Utils.decodeFromUrlSafeString(input), WebAuthnAttestationObject.class);

        //Then
        assertThat(result).isNotNull();
        assertThat(result.getAuthenticatorData()).isNotNull();
        assertThat(result.getFormat()).isEqualTo("fido-u2f");
        assertThat(result.getAttestationStatement()).isNotNull();
        assertThat(result.getAttestationStatement()).isInstanceOf(FIDOU2FAttestationStatement.class);

    }
}
