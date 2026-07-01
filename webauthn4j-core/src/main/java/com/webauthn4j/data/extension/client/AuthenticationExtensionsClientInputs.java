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

package com.webauthn4j.data.extension.client;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.HMACGetSecretInput;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.*;
import java.util.stream.Collectors;

/**
 * {@link AuthenticationExtensionsClientInputs} is a map containing the client extension input values for
 * zero or more WebAuthn extensions, as defined in §9 WebAuthn Extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientinputs">
 * §5.7.1. Authentication Extensions Client Inputs (typedef AuthenticationExtensionsClientInputs)</a>
 */
public class AuthenticationExtensionsClientInputs<T extends ExtensionClientInput> {

    private static final List<Class<? extends ExtensionClientInput>> KNOWN_TYPES = List.of(
            FIDOAppIDExtensionClientInput.class,
            FIDOAppIDExclusionExtensionClientInput.class,
            UserVerificationMethodExtensionClientInput.class,
            CredentialPropertiesExtensionClientInput.class,
            CredentialProtectionExtensionClientInput.class,
            HMACSecretRegistrationExtensionClientInput.class,
            HMACSecretAuthenticationExtensionClientInput.class,
            LargeBlobExtensionClientInput.class,
            PRFExtensionClientInput.class
    );

    private static final Set<String> KNOWN_KEYS = Set.of(
            FIDOAppIDExtensionClientInput.KEY_APPID,
            FIDOAppIDExclusionExtensionClientInput.KEY_APPID_EXCLUDE,
            UserVerificationMethodExtensionClientInput.KEY_UVM,
            CredentialPropertiesExtensionClientInput.KEY_CRED_PROPS,
            CredentialProtectionExtensionClientInput.KEY_CREDENTIAL_PROTECTION_POLICY,
            CredentialProtectionExtensionClientInput.KEY_ENFORCE_CREDENTIAL_PROTECTION_POLICY,
            HMACSecretRegistrationExtensionClientInput.KEY_HMAC_CREATE_SECRET,
            HMACSecretAuthenticationExtensionClientInput.KEY_HMAC_GET_SECRET,
            LargeBlobExtensionClientInput.KEY_LARGE_BLOB,
            PRFExtensionClientInput.KEY_PRF
    );

    @JsonIgnore
    private final ObjectNode rawData;

    @JsonIgnore
    private final ObjectConverter objectConverter;

    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    public AuthenticationExtensionsClientInputs() {
        this(tools.jackson.databind.node.JsonNodeFactory.instance.objectNode(),
                new ObjectConverter());
    }

    // Extension data is stored as raw ObjectNode and deserialized lazily via treeToValue when accessed.
    // Since future extensions may embed CBOR within JSON and require a customized CborMapper for
    // deserialization, ObjectConverter (which pairs both JsonMapper and CborMapper with WebAuthn4J
    // modules) is used rather than a bare JsonMapper.
    public AuthenticationExtensionsClientInputs(
            @NotNull ObjectNode rawData,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(rawData, "rawData must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.rawData = rawData;
        this.objectConverter = objectConverter;
    }

    @JsonValue
    private ObjectNode getRawData() {
        return this.rawData;
    }

    @JsonIgnore
    public @NotNull Set<String> getKeys() {
        return rawData.properties().stream()
                .map(Map.Entry::getKey)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Returns keys not recognized by webauthn4j-core.
     * Note: Extensions registered by external modules via Jackson Module are also
     * reported as "unknown" by this method, even though they have valid deserializers.
     * Use {@link #getKeys()} and filter as needed instead.
     *
     * @deprecated This method only reflects extensions known to webauthn4j-core.
     */
    @Deprecated
    @JsonIgnore
    public @NotNull Set<String> getUnknownKeys() {
        return getKeys().stream()
                .filter(key -> !KNOWN_KEYS.contains(key))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @JsonIgnore
    public @Nullable Object getValue(@NotNull String key) {
        switch (key) {
            case FIDOAppIDExtensionClientInput.KEY_APPID:
                return getAppid();
            case FIDOAppIDExclusionExtensionClientInput.KEY_APPID_EXCLUDE:
                return getAppidExclude();
            case UserVerificationMethodExtensionClientInput.KEY_UVM:
                return getUvm();
            case CredentialPropertiesExtensionClientInput.KEY_CRED_PROPS:
                return getCredProps();
            // credProtect uses two top-level keys for a single extension (see CredentialProtectionExtensionClientInput)
            case CredentialProtectionExtensionClientInput.KEY_CREDENTIAL_PROTECTION_POLICY:
                return getCredentialProtectionPolicy();
            case CredentialProtectionExtensionClientInput.KEY_ENFORCE_CREDENTIAL_PROTECTION_POLICY:
                return getEnforceCredentialProtectionPolicy();
            case HMACSecretRegistrationExtensionClientInput.KEY_HMAC_CREATE_SECRET:
                return getHMACCreateSecret();
            case HMACSecretAuthenticationExtensionClientInput.KEY_HMAC_GET_SECRET:
                return getHMACGetSecret();
            case LargeBlobExtensionClientInput.KEY_LARGE_BLOB:
                return getLargeBlob();
            case PRFExtensionClientInput.KEY_PRF:
                return getPrf();
            default:
                JsonNode node = rawData.get(key);
                if (node == null || node.isNull()) return null;
                if (node.isBoolean()) return node.asBoolean();
                if (node.isString()) return node.textValue();
                if (node.isInt()) return node.asInt();
                if (node.isLong()) return node.asLong();
                if (node.isDouble()) return node.asDouble();
                return objectConverter.getJsonMapper().treeToValue(node, Object.class);
        }
    }

    @JsonIgnore
    public @Nullable String getAppid() {
        FIDOAppIDExtensionClientInput ext = lookupExtension(FIDOAppIDExtensionClientInput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable String getAppidExclude() {
        FIDOAppIDExclusionExtensionClientInput ext = lookupExtension(FIDOAppIDExclusionExtensionClientInput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable Boolean getUvm() {
        UserVerificationMethodExtensionClientInput ext = lookupExtension(UserVerificationMethodExtensionClientInput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable Boolean getCredProps() {
        CredentialPropertiesExtensionClientInput ext = lookupExtension(CredentialPropertiesExtensionClientInput.class);
        return ext != null ? ext.getValue() : null;
    }

    // credProtect is a single extension that spans two JSON keys ("credentialProtectionPolicy" and
    // "enforceCredentialProtectionPolicy"), so two convenience getters delegate to the same extension class.
    @JsonIgnore
    public @Nullable CredentialProtectionPolicy getCredentialProtectionPolicy() {
        CredentialProtectionExtensionClientInput ext = lookupExtension(CredentialProtectionExtensionClientInput.class);
        return ext != null ? ext.getCredentialProtectionPolicy() : null;
    }

    @JsonIgnore
    public @Nullable Boolean getEnforceCredentialProtectionPolicy() {
        CredentialProtectionExtensionClientInput ext = lookupExtension(CredentialProtectionExtensionClientInput.class);
        return ext != null ? ext.getEnforceCredentialProtectionPolicy() : null;
    }

    @JsonIgnore
    public @Nullable Boolean getHMACCreateSecret() {
        HMACSecretRegistrationExtensionClientInput ext = lookupExtension(HMACSecretRegistrationExtensionClientInput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable HMACGetSecretInput getHMACGetSecret() {
        HMACSecretAuthenticationExtensionClientInput ext = lookupExtension(HMACSecretAuthenticationExtensionClientInput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable AuthenticationExtensionsLargeBlobInputs getLargeBlob() {
        LargeBlobExtensionClientInput ext = lookupExtension(LargeBlobExtensionClientInput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable AuthenticationExtensionsPRFInputs getPrf() {
        PRFExtensionClientInput ext = lookupExtension(PRFExtensionClientInput.class);
        return ext != null ? ext.getValue() : null;
    }


    @SuppressWarnings("unchecked")
    public @Nullable <E extends T> E getExtension(Class<E> tClass) {
        E cached = (E) getExtensions().get(tClass);
        if (cached != null) return cached;
        return objectConverter.getJsonMapper().treeToValue(rawData, tClass);
    }

    // unconstrained lookup for internal use by convenience getters
    @SuppressWarnings("unchecked")
    private @Nullable <E extends ExtensionClientInput> E lookupExtension(@NotNull Class<E> tClass) {
        return (E) getExtensions().get(tClass);
    }

    /**
     * Returns a map of extensions known to webauthn4j-core that are present in the data.
     * Note: Extensions registered by external modules via Jackson Module are NOT included
     * in this map. Use {@link #getExtension(Class)} to retrieve specific extensions instead.
     *
     * @deprecated This method only reflects extensions known to webauthn4j-core.
     */
    @Deprecated
    @SuppressWarnings("unchecked")
    @JsonIgnore
    public @NotNull Map<Class<? extends T>, T> getExtensions() {
        if (extensions == null) {
            Map<Class<? extends T>, T> map = new HashMap<>();
            for (Class<? extends ExtensionClientInput> type : KNOWN_TYPES) {
                Object ext = objectConverter.getJsonMapper().treeToValue(rawData, type);
                if (ext != null) {
                    map.put((Class<? extends T>) type, (T) ext);
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
        AuthenticationExtensionsClientInputs<?> that = (AuthenticationExtensionsClientInputs<?>) o;
        return Objects.equals(rawData, that.rawData);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rawData);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("AuthenticationExtensionsClientInputs(");
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

        public @NotNull AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> build() {
            ObjectNode rawData = objectConverter.getJsonMapper().valueToTree(values);
            return new AuthenticationExtensionsClientInputs<>(rawData, objectConverter);
        }

        public @NotNull BuilderForRegistration setObjectConverter(@NotNull ObjectConverter objectConverter) {
            this.objectConverter = objectConverter;
            return this;
        }

        public @NotNull BuilderForRegistration setUvm(@Nullable Boolean uvm) {
            if (uvm != null) values.put("uvm", uvm);
            return this;
        }

        public @NotNull BuilderForRegistration setCredProps(@Nullable Boolean credProps) {
            if (credProps != null) values.put("credProps", credProps);
            return this;
        }

        public @NotNull BuilderForRegistration setCredentialProtectionPolicy(@Nullable CredentialProtectionPolicy credentialProtectionPolicy) {
            if (credentialProtectionPolicy != null) values.put("credentialProtectionPolicy", credentialProtectionPolicy);
            return this;
        }

        public @NotNull BuilderForRegistration setEnforceCredentialProtectionPolicy(@Nullable Boolean enforceCredentialProtectionPolicy) {
            if (enforceCredentialProtectionPolicy != null) values.put("enforceCredentialProtectionPolicy", enforceCredentialProtectionPolicy);
            return this;
        }

        public @NotNull BuilderForRegistration setHMACCreateSecret(@Nullable Boolean hmacCreateSecret) {
            if (hmacCreateSecret != null) values.put("hmacCreateSecret", hmacCreateSecret);
            return this;
        }

        public @NotNull BuilderForRegistration setLargeBlob(@Nullable AuthenticationExtensionsLargeBlobInputs largeBlob) {
            if (largeBlob != null) values.put("largeBlob", largeBlob);
            return this;
        }

        public @NotNull BuilderForRegistration setPrf(@Nullable AuthenticationExtensionsPRFInputs prf) {
            if (prf != null) values.put("prf", prf);
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

        public @NotNull AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> build() {
            ObjectNode rawData = objectConverter.getJsonMapper().valueToTree(values);
            return new AuthenticationExtensionsClientInputs<>(rawData, objectConverter);
        }

        public @NotNull BuilderForAuthentication setObjectConverter(@NotNull ObjectConverter objectConverter) {
            this.objectConverter = objectConverter;
            return this;
        }

        public @NotNull BuilderForAuthentication setAppid(@Nullable String appid) {
            if (appid != null) values.put("appid", appid);
            return this;
        }

        public @NotNull BuilderForAuthentication setAppidExclude(@Nullable String appidExclude) {
            if (appidExclude != null) values.put("appidExclude", appidExclude);
            return this;
        }

        public @NotNull BuilderForAuthentication setUvm(@Nullable Boolean uvm) {
            if (uvm != null) values.put("uvm", uvm);
            return this;
        }

        public @NotNull BuilderForAuthentication setHMACGetSecret(@Nullable HMACGetSecretInput hmacGetSecret) {
            if (hmacGetSecret != null) values.put("hmacGetSecret", hmacGetSecret);
            return this;
        }

        public @NotNull BuilderForAuthentication setLargeBlob(@Nullable AuthenticationExtensionsLargeBlobInputs largeBlob) {
            if (largeBlob != null) values.put("largeBlob", largeBlob);
            return this;
        }

        public @NotNull BuilderForAuthentication setPrf(@Nullable AuthenticationExtensionsPRFInputs prf) {
            if (prf != null) values.put("prf", prf);
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
