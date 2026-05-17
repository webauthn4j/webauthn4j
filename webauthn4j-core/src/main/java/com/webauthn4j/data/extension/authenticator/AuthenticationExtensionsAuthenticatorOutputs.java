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


package com.webauthn4j.data.extension.authenticator;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.*;
import java.util.stream.Collectors;

public class AuthenticationExtensionsAuthenticatorOutputs<T extends ExtensionAuthenticatorOutput> {

    private static final List<Class<? extends ExtensionAuthenticatorOutput>> KNOWN_TYPES = List.of(
            UserVerificationMethodExtensionAuthenticatorOutput.class,
            CredentialProtectionExtensionAuthenticatorOutput.class,
            HMACSecretRegistrationExtensionAuthenticatorOutput.class,
            HMACSecretAuthenticationExtensionAuthenticatorOutput.class
    );

    private static final Set<String> KNOWN_KEYS = Set.of(
            UserVerificationMethodExtensionAuthenticatorOutput.KEY_UVM,
            CredentialProtectionExtensionAuthenticatorOutput.KEY_CRED_PROTECT,
            HMACSecretRegistrationExtensionAuthenticatorOutput.KEY_HMAC_SECRET
    );

    @JsonIgnore
    private final ObjectNode rawData;

    @JsonIgnore
    private final ObjectConverter objectConverter;

    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    public AuthenticationExtensionsAuthenticatorOutputs() {
        this(tools.jackson.databind.node.JsonNodeFactory.instance.objectNode(),
                new ObjectConverter());
    }

    // Extension data is stored as raw ObjectNode and deserialized lazily via treeToValue when accessed.
    // Since future extensions may embed JSON within CBOR and require a customized JsonMapper for
    // deserialization, ObjectConverter (which pairs both CborMapper and JsonMapper with WebAuthn4J
    // modules) is used rather than a bare CborMapper.
    public AuthenticationExtensionsAuthenticatorOutputs(
            @NotNull ObjectNode rawData,
            @NotNull ObjectConverter objectConverter) {
        this.rawData = rawData;
        this.objectConverter = objectConverter;
    }

    @JsonValue
    private ObjectNode getRawData() {
        return this.rawData;
    }

    @JsonIgnore
    public @NotNull Set<String> getKeys() {
        if (rawData == null) return Set.of();
        return rawData.properties().stream()
                .map(Map.Entry::getKey)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @JsonIgnore
    public @NotNull Set<String> getUnknownKeys() {
        return getKeys().stream()
                .filter(key -> !KNOWN_KEYS.contains(key))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @JsonIgnore
    public @Nullable Object getValue(@NotNull String key) {
        switch (key) {
            case UserVerificationMethodExtensionAuthenticatorOutput.KEY_UVM:
                return getUvm();
            case CredentialProtectionExtensionAuthenticatorOutput.KEY_CRED_PROTECT:
                return getCredProtect();
            case HMACSecretRegistrationExtensionAuthenticatorOutput.KEY_HMAC_SECRET:
                return getHMACSecret();
            default:
                if (rawData == null) return null;
                JsonNode node = rawData.get(key);
                if (node == null || node.isNull()) return null;
                if (node.isBoolean()) return node.asBoolean();
                if (node.isString()) return node.textValue();
                if (node.isInt()) return node.asInt();
                if (node.isLong()) return node.asLong();
                if (node.isDouble()) return node.asDouble();
                return objectConverter.getCborMapper().treeToValue(node, Object.class);
        }
    }

    @JsonIgnore
    public @Nullable UvmEntries getUvm() {
        UserVerificationMethodExtensionAuthenticatorOutput ext = lookupExtension(UserVerificationMethodExtensionAuthenticatorOutput.class);
        return ext != null ? ext.getUvm() : null;
    }

    @JsonIgnore
    public @Nullable CredentialProtectionPolicy getCredProtect() {
        CredentialProtectionExtensionAuthenticatorOutput ext = lookupExtension(CredentialProtectionExtensionAuthenticatorOutput.class);
        return ext != null ? ext.getCredProtect() : null;
    }

    public @Nullable Object getHMACSecret() {
        Boolean hmacCreateSecret = getHMACCreateSecret();
        if (hmacCreateSecret != null) return hmacCreateSecret;
        return getHMACGetSecret();
    }

    @JsonIgnore
    public @Nullable Boolean getHMACCreateSecret() {
        HMACSecretRegistrationExtensionAuthenticatorOutput ext = lookupExtension(HMACSecretRegistrationExtensionAuthenticatorOutput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable byte[] getHMACGetSecret() {
        HMACSecretAuthenticationExtensionAuthenticatorOutput ext = lookupExtension(HMACSecretAuthenticationExtensionAuthenticatorOutput.class);
        return ext != null ? ext.getValue() : null;
    }

    @SuppressWarnings("unchecked")
    public @Nullable <E extends T> E getExtension(@NotNull Class<E> tClass) {
        E cached = (E) getExtensions().get(tClass);
        if (cached != null) return cached;
        // Fall back to treeToValue for extensions not in KNOWN_TYPES
        // (e.g. extensions registered by external modules via Jackson Module)
        return objectConverter.getCborMapper().treeToValue(rawData, tClass);
    }

    // unconstrained lookup for internal use by convenience getters
    @SuppressWarnings("unchecked")
    private @Nullable <E extends ExtensionAuthenticatorOutput> E lookupExtension(@NotNull Class<E> tClass) {
        return (E) getExtensions().get(tClass);
    }

    @SuppressWarnings("unchecked")
    @JsonIgnore
    public @NotNull Map<Class<? extends T>, T> getExtensions() {
        if (extensions == null) {
            Map<Class<? extends T>, T> map = new HashMap<>();
            if (rawData != null) {
                for (Class<? extends ExtensionAuthenticatorOutput> type : KNOWN_TYPES) {
                    Object ext = objectConverter.getCborMapper().treeToValue(rawData, type);
                    if (ext != null) {
                        map.put((Class<? extends T>) type, (T) ext);
                    }
                }
            }
            extensions = Collections.unmodifiableMap(map);
        }
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsAuthenticatorOutputs<?> that = (AuthenticationExtensionsAuthenticatorOutputs<?>) o;
        return Objects.equals(rawData, that.rawData);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rawData);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("AuthenticationExtensionsAuthenticatorOutputs(");
        String entries = getKeys().stream()
                .map(key -> String.format("%s=%s", key, getValue(key)))
                .collect(Collectors.joining(", "));
        builder.append(entries);
        builder.append(")");
        return builder.toString();
    }

    public static class BuilderForRegistration {

        private final Map<String, Object> values = new LinkedHashMap<>();
        private ObjectConverter objectConverter = new ObjectConverter();

        public @NotNull AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> build() {
            ObjectNode rawData = objectConverter.getCborMapper().valueToTree(values);
            return new AuthenticationExtensionsAuthenticatorOutputs<>(rawData, objectConverter);
        }

        public @NotNull BuilderForRegistration setObjectConverter(@NotNull ObjectConverter objectConverter) {
            this.objectConverter = objectConverter;
            return this;
        }

        public @NotNull BuilderForRegistration setUvm(@Nullable UvmEntries uvm) {
            if (uvm != null) values.put("uvm", uvm);
            return this;
        }

        public @NotNull BuilderForRegistration setCredProtect(@Nullable CredentialProtectionPolicy credProtect) {
            if (credProtect != null) values.put("credProtect", credProtect);
            return this;
        }

        public @NotNull BuilderForRegistration setHMACCreateSecret(@Nullable Boolean hmacCreateSecret) {
            if (hmacCreateSecret != null) values.put("hmac-secret", hmacCreateSecret);
            return this;
        }

        public @NotNull BuilderForRegistration set(@NotNull String key, @Nullable Object value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            values.put(key, value);
            return this;
        }

    }

    public static class BuilderForAuthentication {

        private final Map<String, Object> values = new LinkedHashMap<>();
        private ObjectConverter objectConverter = new ObjectConverter();

        public @NotNull AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> build() {
            ObjectNode rawData = objectConverter.getCborMapper().valueToTree(values);
            return new AuthenticationExtensionsAuthenticatorOutputs<>(rawData, objectConverter);
        }

        public @NotNull BuilderForAuthentication setObjectConverter(@NotNull ObjectConverter objectConverter) {
            this.objectConverter = objectConverter;
            return this;
        }

        public @NotNull BuilderForAuthentication setUvm(@Nullable UvmEntries uvm) {
            if (uvm != null) values.put("uvm", uvm);
            return this;
        }

        public @NotNull BuilderForAuthentication setHMACGetSecret(@Nullable byte[] hmacGetSecret) {
            if (hmacGetSecret != null) values.put("hmac-secret", hmacGetSecret);
            return this;
        }

        public @NotNull BuilderForAuthentication set(@NotNull String key, @Nullable Object value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            values.put(key, value);
            return this;
        }

    }

}
