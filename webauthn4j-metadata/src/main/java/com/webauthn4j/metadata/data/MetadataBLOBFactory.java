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

package com.webauthn4j.metadata.data;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import org.checkerframework.checker.nullness.qual.NonNull;

public class MetadataBLOBFactory {

    @NonNull
    private final JWSFactory jwsFactory;

    public MetadataBLOBFactory(@NonNull ObjectConverter objectConverter) {
        this.jwsFactory = new JWSFactory(objectConverter);
    }

    public @NonNull MetadataBLOB parse(@NonNull String value){
        JWS<MetadataBLOBPayload> jws = jwsFactory.parse(value, MetadataBLOBPayload.class);
        return new MetadataBLOB(jws);
    }

}
