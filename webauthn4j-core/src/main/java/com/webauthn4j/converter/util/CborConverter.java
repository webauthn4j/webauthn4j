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

package com.webauthn4j.converter.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.jackson.WebAuthnCBORModule;
import com.webauthn4j.util.AssertUtil;

/**
 * A utility class for CBOR serialization/deserialization
 */
public class CborConverter extends AbstractCborConverter {
    public CborConverter(ObjectMapper cborMapper) {
        AssertUtil.notNull(cborMapper, "cborMapper must not be null");

        AssertUtil.isTrue(cborMapper.getFactory() instanceof CBORFactory, "factory of cborMapper must be CBORFactory.");

        this.cborMapper = cborMapper;
        this.cborMapper.registerModule(new WebAuthnCBORModule(this));
        this.cborMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
        this.cborMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.cborMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

    }

    public CborConverter() {
        this(new ObjectMapper(new CBORFactory()));
    }

}
