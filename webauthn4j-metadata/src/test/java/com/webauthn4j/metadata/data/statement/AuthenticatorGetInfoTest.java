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
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticatorGetInfoTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();


    @Test
    void test(){
        AuthenticatorGetInfo authenticatorGetInfo = createAuthenticatorGetInfo();
        assertThat(authenticatorGetInfo.getVersions()).containsExactly("U2F_V2", "FIDO_2_0");
        assertThat(authenticatorGetInfo.getExtensions()).containsExactly("credProtect", "hmac-secret");
        assertThat(authenticatorGetInfo.getAaguid()).isEqualTo(new AAGUID("0132d110-bf4e-4208-a403-ab4f5f12efe5"));
        assertThat(authenticatorGetInfo.getOptions()).isEqualTo(new AuthenticatorGetInfo.Options(
                AuthenticatorGetInfo.Options.PlatformOption.CROSS_PLATFORM,
                AuthenticatorGetInfo.Options.ResidentKeyOption.SUPPORTED,
                AuthenticatorGetInfo.Options.ClientPINOption.SET,
                AuthenticatorGetInfo.Options.UserPresenceOption.SUPPORTED,
                AuthenticatorGetInfo.Options.UserVerificationOption.READY,
                AuthenticatorGetInfo.Options.UVTokenOption.NOT_SUPPORTED,
                AuthenticatorGetInfo.Options.ConfigOption.NOT_SUPPORTED
            )
        );
        assertThat(authenticatorGetInfo.getMaxMsgSize()).isEqualTo(1200);
        assertThat(authenticatorGetInfo.getPinUvAuthProtocols()).containsExactly(AuthenticatorGetInfo.PinProtocolVersion.VERSION_1);
    }

    private AuthenticatorGetInfo createAuthenticatorGetInfo(){
        String authenticatorGetInfoString = "{\n" +
                "      \"versions\": [ \"U2F_V2\", \"FIDO_2_0\" ],\n" +
                "      \"extensions\": [ \"credProtect\", \"hmac-secret\" ],\n" +
                "      \"aaguid\": \"0132d110bf4e4208a403ab4f5f12efe5\",\n" +
                "      \"options\": {\n" +
                "        \"plat\": false,\n" +
                "        \"rk\": true,\n" +
                "        \"clientPin\": true,\n" +
                "        \"up\": true,\n" +
                "        \"uv\": true,\n" +
                "        \"uvToken\": false,\n" +
                "        \"config\": false\n" +
                "      },\n" +
                "      \"maxMsgSize\": 1200,\n" +
                "      \"pinUvAuthProtocols\": [1],\n" +
                "      \"maxCredentialCountInList\": 16,\n" +
                "      \"maxCredentialIdLength\": 128,\n" +
                "      \"transports\": [\"usb\", \"nfc\"],\n" +
                "      \"algorithms\": [{\n" +
                "          \"type\": \"public-key\",\n" +
                "          \"alg\": -7\n" +
                "        },\n" +
                "        {\n" +
                "          \"type\": \"public-key\",\n" +
                "          \"alg\": -257\n" +
                "        }\n" +
                "      ],\n" +
                "      \"maxAuthenticatorConfigLength\": 1024,\n" +
                "      \"defaultCredProtect\": 2,\n" +
                "      \"firmwareVersion\": 5\n" +
                "  }";
        return jsonMapper.readValue(authenticatorGetInfoString, AuthenticatorGetInfo.class);
    }

}