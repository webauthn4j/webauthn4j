package com.webauthn4j.data.extension.client;


import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.HMACGetSecretInput;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;
import java.util.stream.Collectors;

/**
 * {@link com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs} is a map containing the client extension input values for
 * zero or more WebAuthn extensions, as defined in §9 WebAuthn Extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-authenticationextensionsclientinputs">
 * §5.7. Authentication Extensions Client Inputs (typedef AuthenticationExtensionsClientInputs)</a>
 */
public class AuthenticationExtensionsClientInputs<T extends ExtensionClientInput> {

    @JsonIgnore
    private final Map<String, Object> unknowns = new HashMap<>();
    @JsonProperty
    private String appid;
    @JsonProperty
    private String appidExclude;
    @JsonProperty
    private Boolean uvm;
    @JsonProperty
    private Boolean credProps;
    @JsonProperty
    private CredentialProtectionPolicy credentialProtectionPolicy;
    @JsonProperty
    private Boolean enforceCredentialProtectionPolicy;
    @JsonProperty
    private Boolean hmacCreateSecret;
    @JsonProperty
    private HMACGetSecretInput hmacGetSecret;
    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    @JsonAnyGetter
    private @NonNull Map<String, Object> getUnknowns() {
        return Collections.unmodifiableMap(this.unknowns);
    }

    @JsonAnySetter
    private void setUnknowns(@NonNull String name, @Nullable Object value) {
        this.unknowns.put(name, value);
    }

    @JsonIgnore
    public @NonNull Set<String> getKeys() {
        Set<String> keys = new HashSet<>();
        if (appid != null) {
            keys.add("appid");
        }
        if (appidExclude != null) {
            keys.add("appidExclude");
        }
        if (uvm != null) {
            keys.add("uvm");
        }
        if (credProps != null) {
            keys.add("credProps");
        }
        if (credentialProtectionPolicy != null) {
            keys.add("credentialProtectionPolicy");
        }
        if (enforceCredentialProtectionPolicy != null) {
            keys.add("enforceCredentialProtectionPolicy");
        }
        if(hmacCreateSecret != null){
            keys.add("hmacCreateSecret");
        }
        if(hmacGetSecret != null){
            keys.add("hmacGetSecret");
        }
        keys.addAll(getUnknownKeys());
        return keys;
    }

    @JsonIgnore
    public @NonNull Set<String> getUnknownKeys() {
        return unknowns.keySet();
    }

    @JsonIgnore
    public @Nullable Object getValue(@NonNull String key) {
        switch (key) {
            case "appid":
                return appid;
            case "appidExclude":
                return appidExclude;
            case "uvm":
                return uvm;
            case "credProps":
                return credProps;
            case "credentialProtectionPolicy":
                return credentialProtectionPolicy;
            case "enforceCredentialProtectionPolicy":
                return enforceCredentialProtectionPolicy;
            case "hmacCreateSecret":
                return hmacCreateSecret;
            case "hmacGetSecret":
                return hmacGetSecret;
            default:
                return unknowns.get(key);
        }
    }

    @JsonIgnore
    public @Nullable String getAppid() {
        return this.appid;
    }

    @JsonIgnore
    public @Nullable String getAppidExclude() {
        return this.appidExclude;
    }

    @JsonIgnore
    public @Nullable Boolean getUvm() {
        return this.uvm;
    }

    @JsonIgnore
    public @Nullable Boolean getCredProps() {
        return this.credProps;
    }

    @JsonIgnore
    public @Nullable CredentialProtectionPolicy getCredentialProtectionPolicy() {
        return this.credentialProtectionPolicy;
    }

    @JsonIgnore
    public @Nullable Boolean getEnforceCredentialProtectionPolicy() {
        return this.enforceCredentialProtectionPolicy;
    }

    @JsonIgnore
    public @Nullable Boolean getHMACCreateSecret() {
        return hmacCreateSecret;
    }

    @JsonIgnore
    public @Nullable HMACGetSecretInput getHMACGetSecret() {
        return hmacGetSecret;
    }

    @SuppressWarnings("unchecked")
    public @Nullable <E extends T> E getExtension(Class<E> tClass) {
        return (E) getExtensions().get(tClass);
    }

    @SuppressWarnings("unchecked")
    @JsonIgnore
    public @NonNull Map<Class<? extends T>, T> getExtensions() {
        if (extensions == null) {
            Map<Class<? extends T>, T> map = new HashMap<>();
            if (appid != null) {
                map.put((Class<? extends T>) FIDOAppIDExtensionClientInput.class, (T) new FIDOAppIDExtensionClientInput(appid));
            }
            if (appidExclude != null) {
                map.put((Class<? extends T>) FIDOAppIDExclusionExtensionClientInput.class, (T) new FIDOAppIDExclusionExtensionClientInput(appidExclude));
            }
            if (uvm != null) {
                map.put((Class<? extends T>) UserVerificationMethodExtensionClientInput.class, (T) new UserVerificationMethodExtensionClientInput(uvm));
            }
            if (credProps != null) {
                map.put((Class<? extends T>) CredentialPropertiesExtensionClientInput.class, (T) new CredentialPropertiesExtensionClientInput(credProps));
            }
            if (credentialProtectionPolicy != null) {
                map.put((Class<? extends T>) CredentialProtectionExtensionClientInput.class, (T) new CredentialProtectionExtensionClientInput(credentialProtectionPolicy, enforceCredentialProtectionPolicy));
            }
            if (hmacCreateSecret != null) {
                map.put((Class<? extends T>) HMACSecretRegistrationExtensionClientInput.class, (T) new HMACSecretRegistrationExtensionClientInput(hmacCreateSecret));
            }
            if (hmacGetSecret != null) {
                map.put((Class<? extends T>) HMACSecretAuthenticationExtensionClientInput.class, (T) new HMACSecretAuthenticationExtensionClientInput(hmacGetSecret));
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
        return Objects.equals(unknowns, that.unknowns) && Objects.equals(appid, that.appid) && Objects.equals(appidExclude, that.appidExclude) && Objects.equals(uvm, that.uvm) && Objects.equals(credProps, that.credProps) && credentialProtectionPolicy == that.credentialProtectionPolicy && Objects.equals(enforceCredentialProtectionPolicy, that.enforceCredentialProtectionPolicy) && Objects.equals(hmacCreateSecret, that.hmacCreateSecret) && Objects.equals(hmacGetSecret, that.hmacGetSecret) && Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(unknowns, appid, appidExclude, uvm, credProps, credentialProtectionPolicy, enforceCredentialProtectionPolicy, hmacCreateSecret, hmacGetSecret, extensions);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("AuthenticationExtensionsAuthenticatorInputs(");
        String entries = getExtensions().values().stream().map(t -> String.format("%s=%s", t.getIdentifier(), t)).collect(Collectors.joining(", "));
        builder.append(entries);
        String unknownsStr = getUnknowns().entrySet().stream().map(entry -> String.format("%s=%s", entry.getKey(), entry.getValue())).collect(Collectors.joining(", "));
        if(!unknownsStr.isEmpty()){
            builder.append(", ");
            builder.append(unknownsStr);
        }
        builder.append(")");
        return builder.toString();
    }

    public static class BuilderForRegistration {

        private final Map<String, Object> unknowns = new HashMap<>();
        private Boolean uvm;
        private Boolean credProps;
        private CredentialProtectionPolicy credentialProtectionPolicy;
        private Boolean enforceCredentialProtectionPolicy;
        private Boolean hmacCreateSecret;

        public @NonNull AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> build() {
            AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> instance = new AuthenticationExtensionsClientInputs<>();
            instance.uvm = this.uvm;
            instance.credProps = this.credProps;
            instance.credentialProtectionPolicy = this.credentialProtectionPolicy;
            instance.enforceCredentialProtectionPolicy = this.enforceCredentialProtectionPolicy;
            instance.hmacCreateSecret = this.hmacCreateSecret;
            instance.unknowns.putAll(this.unknowns);

            return instance;
        }

        public @NonNull BuilderForRegistration setUvm(@Nullable Boolean uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NonNull BuilderForRegistration setCredProps(@Nullable Boolean credProps) {
            this.credProps = credProps;
            return this;
        }

        public @NonNull BuilderForRegistration setCredentialProtectionPolicy(@Nullable CredentialProtectionPolicy credentialProtectionPolicy) {
            this.credentialProtectionPolicy = credentialProtectionPolicy;
            return this;
        }

        public @NonNull BuilderForRegistration setEnforceCredentialProtectionPolicy(@Nullable Boolean enforceCredentialProtectionPolicy) {
            this.enforceCredentialProtectionPolicy = enforceCredentialProtectionPolicy;
            return this;
        }

        public @NonNull BuilderForRegistration setHMACCreateSecret(@Nullable Boolean hmacCreateSecret) {
            this.hmacCreateSecret = hmacCreateSecret;
            return this;
        }

        public @NonNull BuilderForRegistration set(@NonNull String key, @Nullable Object value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }

    }

    public static class BuilderForAuthentication {

        private final Map<String, Object> unknowns = new HashMap<>();
        private String appid;
        private String appidExclude;
        private Boolean uvm;
        private HMACGetSecretInput hmacGetSecret;

        public @NonNull AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> build() {
            AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> instance = new AuthenticationExtensionsClientInputs<>();
            instance.appid = this.appid;
            instance.appidExclude = this.appidExclude;
            instance.uvm = this.uvm;
            instance.hmacGetSecret = this.hmacGetSecret;
            instance.unknowns.putAll(this.unknowns);

            return instance;
        }

        public @NonNull BuilderForAuthentication setAppid(@NonNull String appid) {
            this.appid = appid;
            return this;
        }

        public @NonNull BuilderForAuthentication setAppidExclude(@NonNull String appidExclude) {
            this.appidExclude = appidExclude;
            return this;
        }

        public @NonNull BuilderForAuthentication setUvm(@NonNull Boolean uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NonNull BuilderForAuthentication setHMACGetSecret(@Nullable HMACGetSecretInput hmacGetSecret) {
            this.hmacGetSecret = hmacGetSecret;
            return this;
        }

        public @NonNull BuilderForAuthentication set(@NonNull String key, @Nullable Object value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }

    }

}
