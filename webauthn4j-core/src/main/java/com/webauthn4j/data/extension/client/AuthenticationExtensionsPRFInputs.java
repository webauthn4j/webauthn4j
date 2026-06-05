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

package com.webauthn4j.data.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jetbrains.annotations.Nullable;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfinputs">
 * §10.1.4. Pseudo-random function extension (prf)</a>
 */
public class AuthenticationExtensionsPRFInputs {

    private final AuthenticationExtensionsPRFValues eval;
    private final Map<String, AuthenticationExtensionsPRFValues> evalByCredential;

    @JsonCreator
    public AuthenticationExtensionsPRFInputs(
            @Nullable @JsonProperty("eval") AuthenticationExtensionsPRFValues eval,
            @Nullable @JsonProperty("evalByCredential") Map<String, AuthenticationExtensionsPRFValues> evalByCredential) {
        this.eval = eval;
        this.evalByCredential = evalByCredential == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(evalByCredential));
    }

    public @Nullable AuthenticationExtensionsPRFValues getEval() {
        return eval;
    }

    public @Nullable Map<String, AuthenticationExtensionsPRFValues> getEvalByCredential() {
        return evalByCredential;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsPRFInputs that = (AuthenticationExtensionsPRFInputs) o;
        return Objects.equals(eval, that.eval) && Objects.equals(evalByCredential, that.evalByCredential);
    }

    @Override
    public int hashCode() {
        return Objects.hash(eval, evalByCredential);
    }
}
