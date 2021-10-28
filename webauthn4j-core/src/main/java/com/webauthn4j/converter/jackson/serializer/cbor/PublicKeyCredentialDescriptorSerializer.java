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

package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.PublicKeyCredentialDescriptor;

import java.util.Arrays;

public class PublicKeyCredentialDescriptorSerializer extends AbstractCtapCanonicalCborSerializer<PublicKeyCredentialDescriptor> {

    public PublicKeyCredentialDescriptorSerializer() {
        super(PublicKeyCredentialDescriptor.class, Arrays.asList(
                new FieldSerializationRule<>("id", PublicKeyCredentialDescriptor::getId),
                new FieldSerializationRule<>("type", PublicKeyCredentialDescriptor::getType),
                new FieldSerializationRule<>("transports", PublicKeyCredentialDescriptor::getTransports)
        ));
    }
}
