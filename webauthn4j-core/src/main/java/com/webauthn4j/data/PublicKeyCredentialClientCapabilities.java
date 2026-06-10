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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.jetbrains.annotations.NotNull;

import java.util.Collections;
import java.util.Map;

/**
 * Represents the result of PublicKeyCredential.getClientCapabilities(),
 * which is a record mapping {@link ClientCapability} keys to boolean values.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-getclientcapabilities">
 * §5.1.7. Availability of Client Capabilities</a>
 */
public class PublicKeyCredentialClientCapabilities extends AbstractImmutableMap<ClientCapability, Boolean> {

    @JsonCreator
    public PublicKeyCredentialClientCapabilities(@NotNull Map<ClientCapability, Boolean> map) {
        super(map);
    }

    public PublicKeyCredentialClientCapabilities() {
        this(Collections.emptyMap());
    }
}
