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

package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.type.SimpleType;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.IOException;

/**
 * Jackson Serializer for {@link AuthenticationExtensionsAuthenticatorOutputsEnvelope}
 */
public class AuthenticationExtensionsAuthenticatorOutputsEnvelopeDeserializer extends StdDeserializer<AuthenticationExtensionsAuthenticatorOutputsEnvelope<? extends ExtensionAuthenticatorOutput>> {

    public AuthenticationExtensionsAuthenticatorOutputsEnvelopeDeserializer() {
        super(AuthenticationExtensionsAuthenticatorOutputsEnvelope.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @NonNull AuthenticationExtensionsAuthenticatorOutputsEnvelope<? extends ExtensionAuthenticatorOutput> deserialize(@NonNull JsonParser p, @NonNull DeserializationContext ctxt) throws IOException {
        JavaType javaType = SimpleType.constructUnsafe(AuthenticationExtensionsAuthenticatorOutputs.class);
        AuthenticationExtensionsAuthenticatorOutputs<? extends ExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs = ctxt.readValue(p, javaType);
        int length = (int) p.getCurrentLocation().getByteOffset();
        return new AuthenticationExtensionsAuthenticatorOutputsEnvelope<>(authenticationExtensionsAuthenticatorOutputs, length);
    }
}
