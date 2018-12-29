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
import com.webauthn4j.response.extension.client.*;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;

/**
 * Jackson Deserializer for {@link ExtensionClientOutput}
 */
public class ExtensionClientOutputDeserializer extends StdDeserializer<ExtensionClientOutput> {

    public ExtensionClientOutputDeserializer() {
        super(ExtensionClientOutput.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        String currentName = p.getParsingContext().getCurrentName();

        if (currentName != null) {
            switch (currentName) {
                case FIDOAppIDExtensionClientOutput.ID:
                    return ctxt.readValue(p, FIDOAppIDExtensionClientOutput.class);
                case UserVerificationIndexExtensionClientOutput.ID:
                    return ctxt.readValue(p, UserVerificationIndexExtensionClientOutput.class);
                case SimpleTransactionAuthorizationExtensionClientOutput.ID:
                    return ctxt.readValue(p, SimpleTransactionAuthorizationExtensionClientOutput.class);
                case AuthenticatorSelectionExtensionClientOutput.ID:
                    return ctxt.readValue(p, AuthenticatorSelectionExtensionClientOutput.class);
                case BiometricAuthenticatorPerformanceBoundsExtensionClientOutput.ID:
                    return ctxt.readValue(p, BiometricAuthenticatorPerformanceBoundsExtensionClientOutput.class);
                default:
                    throw new NotImplementedException();
            }
        } else {
            String parentName = p.getParsingContext().getParent().getCurrentName();

            switch (parentName) {
                case GenericTransactionAuthorizationExtensionClientOutput.ID:
                    return ctxt.readValue(p, GenericTransactionAuthorizationExtensionClientOutput.class);
                case SupportedExtensionsExtensionClientOutput.ID:
                    return ctxt.readValue(p, SupportedExtensionsExtensionClientOutput.class);
                case UserVerificationIndexExtensionClientOutput.ID:
                    return ctxt.readValue(p, UserVerificationIndexExtensionClientOutput.class);
                case LocationExtensionClientOutput.ID:
                    return ctxt.readValue(p, LocationExtensionClientOutput.class);
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
