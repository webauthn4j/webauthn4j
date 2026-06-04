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

package com.webauthn4j.metadata.converter.jackson;

import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardClearingMixin;
import com.webauthn4j.converter.jackson.deserializer.json.UserVerificationMethodSetFromLongDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.UserVerificationMethodSetToLongSerializer;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.deserializer.AAIDDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.AuthenticatorStatusDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.MetadataAAGUIDRelaxedDeserializer;
import com.webauthn4j.metadata.converter.jackson.serializer.AAIDSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.AuthenticatorStatusSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.MetadataAAGUIDSerializer;
import com.webauthn4j.metadata.data.toc.AuthenticatorStatus;
import com.webauthn4j.metadata.data.uaf.AAID;
import tools.jackson.databind.*;
import tools.jackson.databind.deser.Deserializers;
import tools.jackson.databind.jsontype.TypeDeserializer;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.Serializers;
import tools.jackson.databind.type.CollectionType;

import java.util.Set;

public class WebAuthnMetadataJSONModule extends SimpleModule {

    @SuppressWarnings("deprecation")
    public WebAuthnMetadataJSONModule() {
        super("WebAuthnMetadataJSONModule");

        this.addSerializer(AAGUID.class, new MetadataAAGUIDSerializer());
        this.addDeserializer(AAGUID.class, new MetadataAAGUIDRelaxedDeserializer());

        // These types have @JsonSerialize/@JsonDeserialize guard annotations that are cleared by setupModule() via MixIn.
        this.addSerializer(AAID.class, new AAIDSerializer());
        this.addDeserializer(AAID.class, new AAIDDeserializer());
        this.addSerializer(AuthenticatorStatus.class, new AuthenticatorStatusSerializer());
        this.addDeserializer(AuthenticatorStatus.class, new AuthenticatorStatusDeserializer());
    }

    @Override
    public void setupModule(SetupContext context) {
        super.setupModule(context);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, AAID.class);
        ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, AuthenticatorStatus.class);

        addCollectionSerializer(context, Set.class, UserVerificationMethod.class,
                new UserVerificationMethodSetToLongSerializer());
        addCollectionDeserializer(context, Set.class, UserVerificationMethod.class,
                new UserVerificationMethodSetFromLongDeserializer());
    }

    private static void addCollectionSerializer(SetupContext context,
            Class<?> collectionType, Class<?> elementType, ValueSerializer<?> serializer) {
        context.addSerializers(new Serializers.Base() {
            @Override
            public ValueSerializer<?> findCollectionSerializer(SerializationConfig config,
                    CollectionType type, BeanDescription.Supplier beanDescRef,
                    com.fasterxml.jackson.annotation.JsonFormat.Value formatOverrides,
                    tools.jackson.databind.jsontype.TypeSerializer elementTypeSerializer,
                    ValueSerializer<Object> elementValueSerializer) {
                if (collectionType.isAssignableFrom(type.getRawClass())
                        && type.getContentType().getRawClass() == elementType) {
                    return serializer;
                }
                return null;
            }
        });
    }

    private static void addCollectionDeserializer(SetupContext context,
            Class<?> collectionType, Class<?> elementType, ValueDeserializer<?> deserializer) {
        context.addDeserializers(new Deserializers.Base() {
            @Override
            public ValueDeserializer<?> findCollectionDeserializer(CollectionType type,
                    DeserializationConfig config, BeanDescription.Supplier beanDescRef,
                    TypeDeserializer elementTypeDeserializer,
                    ValueDeserializer<?> elementDeserializer) {
                if (collectionType.isAssignableFrom(type.getRawClass())
                        && type.getContentType().getRawClass() == elementType) {
                    return deserializer;
                }
                return null;
            }

            @Override
            public boolean hasDeserializerFor(DeserializationConfig config, Class<?> valueType) {
                return collectionType.isAssignableFrom(valueType);
            }
        });
    }

}
