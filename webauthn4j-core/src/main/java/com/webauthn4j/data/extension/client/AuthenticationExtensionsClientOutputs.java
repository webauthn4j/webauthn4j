package com.webauthn4j.data.extension.client;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Map containing the client extension output values for zero or more WebAuthn
 * extensions, as defined in §9 WebAuthn Extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputs">§5.7.2. Authentication Extensions Client Outputs</a>
 */
public class AuthenticationExtensionsClientOutputs<T extends ExtensionClientOutput> {

    private static final List<Class<? extends ExtensionClientOutput>> KNOWN_TYPES = List.of(
            FIDOAppIDExtensionClientOutput.class,
            FIDOAppIDExclusionExtensionClientOutput.class,
            UserVerificationMethodExtensionClientOutput.class,
            CredentialPropertiesExtensionClientOutput.class,
            HMACSecretRegistrationExtensionClientOutput.class,
            HMACSecretAuthenticationExtensionClientOutput.class
    );

    private static final Set<String> KNOWN_KEYS = Set.of(
            FIDOAppIDExtensionClientOutput.KEY_APPID,
            FIDOAppIDExclusionExtensionClientOutput.KEY_APPID_EXCLUDE,
            UserVerificationMethodExtensionClientOutput.KEY_UVM,
            CredentialPropertiesExtensionClientOutput.KEY_CRED_PROPS,
            HMACSecretRegistrationExtensionClientOutput.KEY_HMAC_CREATE_SECRET,
            HMACSecretAuthenticationExtensionClientOutput.KEY_HMAC_GET_SECRET
    );

    @JsonIgnore
    private final ObjectNode rawData;

    @JsonIgnore
    private final ObjectConverter objectConverter;

    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    public AuthenticationExtensionsClientOutputs() {
        this(tools.jackson.databind.node.JsonNodeFactory.instance.objectNode(),
                new ObjectConverter());
    }

    // Extension data is stored as raw ObjectNode and deserialized lazily via treeToValue when accessed.
    // Since future extensions may embed CBOR within JSON and require a customized CborMapper for
    // deserialization, ObjectConverter (which pairs both JsonMapper and CborMapper with WebAuthn4J
    // modules) is used rather than a bare JsonMapper.
    public AuthenticationExtensionsClientOutputs(
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
            case FIDOAppIDExtensionClientOutput.KEY_APPID:
                return getAppid();
            case FIDOAppIDExclusionExtensionClientOutput.KEY_APPID_EXCLUDE:
                return getAppidExclude();
            case UserVerificationMethodExtensionClientOutput.KEY_UVM:
                return getUvm();
            case CredentialPropertiesExtensionClientOutput.KEY_CRED_PROPS:
                return getCredProps();
            case HMACSecretRegistrationExtensionClientOutput.KEY_HMAC_CREATE_SECRET:
                return getHMACCreateSecret();
            case HMACSecretAuthenticationExtensionClientOutput.KEY_HMAC_GET_SECRET:
                return getHMACGetSecret();
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
    public @Nullable Boolean getAppid() {
        FIDOAppIDExtensionClientOutput ext = lookupExtension(FIDOAppIDExtensionClientOutput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable Boolean getAppidExclude() {
        FIDOAppIDExclusionExtensionClientOutput ext = lookupExtension(FIDOAppIDExclusionExtensionClientOutput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable UvmEntries getUvm() {
        UserVerificationMethodExtensionClientOutput ext = lookupExtension(UserVerificationMethodExtensionClientOutput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable Boolean getHMACCreateSecret() {
        HMACSecretRegistrationExtensionClientOutput ext = lookupExtension(HMACSecretRegistrationExtensionClientOutput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable HMACGetSecretOutput getHMACGetSecret() {
        HMACSecretAuthenticationExtensionClientOutput ext = lookupExtension(HMACSecretAuthenticationExtensionClientOutput.class);
        return ext != null ? ext.getValue() : null;
    }

    @JsonIgnore
    public @Nullable CredentialPropertiesOutput getCredProps() {
        CredentialPropertiesExtensionClientOutput ext = lookupExtension(CredentialPropertiesExtensionClientOutput.class);
        return ext != null ? ext.getValue() : null;
    }

    @SuppressWarnings("unchecked")
    public @Nullable <E extends T> E getExtension(@NotNull Class<E> tClass) {
        E cached = (E) getExtensions().get(tClass);
        if (cached != null) return cached;
        // Fall back to treeToValue for extensions not in KNOWN_TYPES
        // (e.g. extensions registered by external modules via Jackson Module)
        return objectConverter.getJsonMapper().treeToValue(rawData, tClass);
    }

    // unconstrained lookup for internal use by convenience getters
    @SuppressWarnings("unchecked")
    private @Nullable <E extends ExtensionClientOutput> E lookupExtension(@NotNull Class<E> tClass) {
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
            for (Class<? extends ExtensionClientOutput> type : KNOWN_TYPES) {
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
        AuthenticationExtensionsClientOutputs<?> that = (AuthenticationExtensionsClientOutputs<?>) o;
        return Objects.equals(rawData, that.rawData);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rawData);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("AuthenticationExtensionsClientOutputs(");
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

        public @NotNull AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> build() {
            ObjectNode rawData = objectConverter.getJsonMapper().valueToTree(values);
            return new AuthenticationExtensionsClientOutputs<>(rawData, objectConverter);
        }

        public @NotNull BuilderForRegistration setObjectConverter(@NotNull ObjectConverter objectConverter) {
            this.objectConverter = objectConverter;
            return this;
        }

        public @NotNull BuilderForRegistration setUvm(@Nullable UvmEntries uvm) {
            if (uvm != null) values.put("uvm", uvm);
            return this;
        }

        public @NotNull BuilderForRegistration setCredProps(@Nullable CredentialPropertiesOutput credProps) {
            if (credProps != null) values.put("credProps", credProps);
            return this;
        }

        public @NotNull BuilderForRegistration setHMACCreateSecret(@Nullable Boolean hmacCreateSecret) {
            if (hmacCreateSecret != null) values.put("hmacCreateSecret", hmacCreateSecret);
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

        public @NotNull AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> build() {
            ObjectNode rawData = objectConverter.getJsonMapper().valueToTree(values);
            return new AuthenticationExtensionsClientOutputs<>(rawData, objectConverter);
        }

        public @NotNull BuilderForAuthentication setObjectConverter(@NotNull ObjectConverter objectConverter) {
            this.objectConverter = objectConverter;
            return this;
        }

        public @NotNull BuilderForAuthentication setAppid(@Nullable Boolean appid) {
            if (appid != null) values.put("appid", appid);
            return this;
        }

        public @NotNull BuilderForAuthentication setAppidExclude(@Nullable Boolean appidExclude) {
            if (appidExclude != null) values.put("appidExclude", appidExclude);
            return this;
        }

        public @NotNull BuilderForAuthentication setUvm(@Nullable UvmEntries uvm) {
            if (uvm != null) values.put("uvm", uvm);
            return this;
        }

        public @NotNull BuilderForAuthentication setHMACGetSecret(@Nullable HMACGetSecretOutput hmacGetSecret) {
            if (hmacGetSecret != null) values.put("hmacGetSecret", hmacGetSecret);
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
