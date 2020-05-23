/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.util.AssertUtil;

import java.io.IOException;

/**
 * Jackson Deserializer for {@link AuthenticatorData}
 */
public class AuthenticatorDataDeserializer extends StdDeserializer<AuthenticatorData<? extends ExtensionAuthenticatorOutput<?>>> {

    private final ObjectConverter objectConverter;

    public AuthenticatorDataDeserializer(ObjectConverter objectConverter) {
        super(AuthenticatorData.class);

        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.objectConverter = objectConverter;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthenticatorData<? extends ExtensionAuthenticatorOutput<?>> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        byte[] value = p.getBinaryValue();
        return new AuthenticatorDataConverter(objectConverter).convert(value);
    }


}
