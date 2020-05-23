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
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.introspect.AnnotatedClass;
import com.fasterxml.jackson.databind.introspect.AnnotatedClassResolver;
import com.fasterxml.jackson.databind.jsontype.NamedType;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.UnknownExtensionClientInput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.Objects;

/**
 * Jackson Deserializer for {@link RegistrationExtensionClientInput}
 */
public class RegistrationExtensionClientInputDeserializer extends StdDeserializer<RegistrationExtensionClientInput<?>> {

    private transient Logger logger = LoggerFactory.getLogger(RegistrationExtensionClientInputDeserializer.class);

    public RegistrationExtensionClientInputDeserializer() {
        super(RegistrationExtensionClientInput.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public RegistrationExtensionClientInput<?> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        String name = p.getParsingContext().getCurrentName();
        if (name == null) {
            name = p.getParsingContext().getParent().getCurrentName();
        }

        DeserializationConfig config = ctxt.getConfig();
        AnnotatedClass annotatedClass = AnnotatedClassResolver.resolveWithoutSuperTypes(config, RegistrationExtensionClientInput.class);
        Collection<NamedType> namedTypes = config.getSubtypeResolver().collectAndResolveSubtypesByClass(config, annotatedClass);

        for (NamedType namedType : namedTypes) {
            if (Objects.equals(namedType.getName(), name)) {
                return (RegistrationExtensionClientInput<?>) ctxt.readValue(p, namedType.getType());
            }
        }

        logger.warn("Unknown extension '{}' is contained.", name);
        return ctxt.readValue(p, UnknownExtensionClientInput.class);
    }
}
