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

package com.webauthn4j.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.authenticator.WebAuthnAttestedCredentialData;
import com.webauthn4j.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.attestation.authenticator.extension.Extension;
import com.webauthn4j.converter.WebAuthnAuthenticatorDataConverter;
import com.webauthn4j.util.UnsignedNumberUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Jackson Serializer for WebAuthnAuthenticatorData
 */
public class WebAuthnAuthenticatorDataSerializer extends StdSerializer<WebAuthnAuthenticatorData> {


    public WebAuthnAuthenticatorDataSerializer() {
        super(WebAuthnAuthenticatorData.class);
    }

    @Override
    public void serialize(WebAuthnAuthenticatorData value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        WebAuthnAuthenticatorDataConverter webAuthnAuthenticatorDataConverter = new WebAuthnAuthenticatorDataConverter();
        gen.writeBinary(webAuthnAuthenticatorDataConverter.convertToBytes(value));
    }

}
