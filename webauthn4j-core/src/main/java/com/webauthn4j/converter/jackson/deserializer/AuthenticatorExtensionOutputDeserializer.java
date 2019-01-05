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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.response.attestation.statement.JWS;
import com.webauthn4j.response.extension.authenticator.*;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;

/**
 * Jackson Deserializer for {@link ExtensionAuthenticatorOutput}
 */
public class AuthenticatorExtensionOutputDeserializer extends StdDeserializer<ExtensionAuthenticatorOutput> {

    public AuthenticatorExtensionOutputDeserializer() {
        super(ExtensionAuthenticatorOutput.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExtensionAuthenticatorOutput deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        String currentName = p.getParsingContext().getCurrentName();

        if (SimpleTransactionAuthorizationExtensionAuthenticatorOutput.ID.equals(currentName)) {
            return ctxt.readValue(p, SimpleTransactionAuthorizationExtensionAuthenticatorOutput.class);
        } else if (UserVerificationIndexExtensionAuthenticatorOutput.ID.equals(currentName)) {
            return ctxt.readValue(p, UserVerificationIndexExtensionAuthenticatorOutput.class);
        }

        String parentName = p.getParsingContext().getParent().getCurrentName();

        switch (parentName) {
            case GenericTransactionAuthorizationExtensionAuthenticatorOutput.ID:
                return ctxt.readValue(p, GenericTransactionAuthorizationExtensionAuthenticatorOutput.class);
            case SupportedExtensionsExtensionAuthenticatorOutput.ID:
                return ctxt.readValue(p, SupportedExtensionsExtensionAuthenticatorOutput.class);
            case LocationExtensionAuthenticatorOutput.ID:
                return ctxt.readValue(p, LocationExtensionAuthenticatorOutput.class);
            case UserVerificationIndexExtensionAuthenticatorOutput.ID:
                return ctxt.readValue(p, UserVerificationIndexExtensionAuthenticatorOutput.class);
            default:
                throw new InvalidFormatException(p, "Invalid JWS", parentName, ExtensionAuthenticatorOutput.class);
        }
    }
}
