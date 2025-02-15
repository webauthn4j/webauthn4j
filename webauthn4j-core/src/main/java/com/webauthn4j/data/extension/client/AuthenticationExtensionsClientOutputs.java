package com.webauthn4j.data.extension.client;


import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Map containing the client extension output values for zero or more WebAuthn
 * extensions, as defined in §9 WebAuthn Extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-authenticationextensionsclientoutputs">§5.8. Authentication Extensions Client Outputs</a>
 */
public class AuthenticationExtensionsClientOutputs<T extends ExtensionClientOutput> {

    @JsonIgnore
    private final Map<String, Object> unknowns = new HashMap<>();
    @JsonProperty
    private Boolean appid;
    @JsonProperty
    private Boolean appidExclude;
    @JsonProperty
    private UvmEntries uvm;
    @JsonProperty
    private CredentialPropertiesOutput credProps;
    @JsonProperty
    private Boolean hmacCreateSecret;
    @JsonProperty
    private HMACGetSecretOutput hmacGetSecret;
    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    @JsonAnySetter
    private void setUnknowns(@NotNull String name, @Nullable Object value) {
        this.unknowns.put(name, value);
    }

    @JsonAnyGetter
    private @NotNull Map<String, Object> getUnknowns() {
        return this.unknowns;
    }

    @JsonIgnore
    public @NotNull Set<String> getKeys() {
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
    public @NotNull Set<String> getUnknownKeys() {
        return unknowns.keySet();
    }

    @JsonIgnore
    public @Nullable Object getValue(@NotNull String key) {
        switch (key) {
            case "appid":
                return appid;
            case "appidExclude":
                return appidExclude;
            case "uvm":
                return uvm;
            case "credProps":
                return credProps;
            case "hmacCreateSecret":
                return hmacCreateSecret;
            case "hmacGetSecret":
                return hmacGetSecret;
            default:
                return unknowns.get(key);
        }
    }

    @JsonIgnore
    public @Nullable Boolean getAppid() {
        return this.appid;
    }

    @JsonIgnore
    public @Nullable Boolean getAppidExclude() {
        return this.appidExclude;
    }

    @JsonIgnore
    public @Nullable UvmEntries getUvm() {
        return this.uvm;
    }

    @JsonIgnore
    public @Nullable Boolean getHMACCreateSecret() {
        return hmacCreateSecret;
    }

    @JsonIgnore
    public @Nullable HMACGetSecretOutput getHMACGetSecret() {
        return hmacGetSecret;
    }

    @JsonIgnore
    public @Nullable CredentialPropertiesOutput getCredProps() {
        return this.credProps;
    }

    @SuppressWarnings("unchecked")
    public @Nullable <E extends T> E getExtension(@NotNull Class<E> tClass) {
        return (E) getExtensions().get(tClass);
    }

    @SuppressWarnings("unchecked")
    @JsonIgnore
    public @NotNull Map<Class<? extends T>, T> getExtensions() {
        if (extensions == null) {
            Map<Class<? extends T>, T> map = new HashMap<>();
            if (appid != null) {
                map.put((Class<? extends T>) FIDOAppIDExtensionClientOutput.class, (T) new FIDOAppIDExtensionClientOutput(appid));
            }
            if (appidExclude != null) {
                map.put((Class<? extends T>) FIDOAppIDExclusionExtensionClientOutput.class, (T) new FIDOAppIDExclusionExtensionClientOutput(appidExclude));
            }
            if (uvm != null) {
                map.put((Class<? extends T>) UserVerificationMethodExtensionClientOutput.class, (T) new UserVerificationMethodExtensionClientOutput(uvm));
            }
            if (credProps != null) {
                map.put((Class<? extends T>) CredentialPropertiesExtensionClientOutput.class, (T) new CredentialPropertiesExtensionClientOutput(credProps));
            }
            if (hmacCreateSecret != null) {
                map.put((Class<? extends T>) HMACSecretRegistrationExtensionClientOutput.class, (T) new HMACSecretRegistrationExtensionClientOutput(hmacCreateSecret));
            }
            if (hmacGetSecret != null) {
                map.put((Class<? extends T>) HMACSecretAuthenticationExtensionClientOutput.class, (T) new HMACSecretAuthenticationExtensionClientOutput(hmacGetSecret));
            }
            extensions = Collections.unmodifiableMap(map);
        }
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsClientOutputs<?> that = (AuthenticationExtensionsClientOutputs<?>) o;
        return Objects.equals(unknowns, that.unknowns) && Objects.equals(appid, that.appid) && Objects.equals(appidExclude, that.appidExclude) && Objects.equals(uvm, that.uvm) && Objects.equals(credProps, that.credProps) && Objects.equals(hmacCreateSecret, that.hmacCreateSecret) && Objects.equals(hmacGetSecret, that.hmacGetSecret) && Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(unknowns, appid, appidExclude, uvm, credProps, hmacCreateSecret, hmacGetSecret, extensions);
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
        private UvmEntries uvm;
        private CredentialPropertiesOutput credProps;
        private Boolean hmacCreateSecret;

        public @NotNull AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> build() {
            AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> instance = new AuthenticationExtensionsClientOutputs<>();
            instance.uvm = this.uvm;
            instance.credProps = this.credProps;
            instance.hmacCreateSecret = this.hmacCreateSecret;
            instance.unknowns.putAll(this.unknowns);

            return instance;
        }

        public @NotNull BuilderForRegistration setUvm(@Nullable UvmEntries uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NotNull BuilderForRegistration setCredProps(@Nullable CredentialPropertiesOutput credProps) {
            this.credProps = credProps;
            return this;
        }

        public @NotNull BuilderForRegistration setHMACCreateSecret(@Nullable Boolean hmacCreateSecret) {
            this.hmacCreateSecret = hmacCreateSecret;
            return this;
        }

        public @NotNull BuilderForRegistration set(@NotNull String key, @Nullable Object value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }

    }

    public static class BuilderForAuthentication {

        private final Map<String, Object> unknowns = new HashMap<>();
        private Boolean appid;
        private Boolean appidExclude;
        private UvmEntries uvm;
        private HMACGetSecretOutput hmacGetSecret;

        public @NotNull AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> build() {
            AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> instance = new AuthenticationExtensionsClientOutputs<>();
            instance.appid = this.appid;
            instance.appidExclude = this.appidExclude;
            instance.uvm = this.uvm;
            instance.hmacGetSecret = this .hmacGetSecret;
            instance.unknowns.putAll(this.unknowns);

            return instance;
        }

        public @NotNull BuilderForAuthentication setAppid(@Nullable Boolean appid) {
            this.appid = appid;
            return this;
        }

        public @NotNull BuilderForAuthentication setAppidExclude(@Nullable Boolean appidExclude) {
            this.appidExclude = appidExclude;
            return this;
        }

        public @NotNull BuilderForAuthentication setUvm(@Nullable UvmEntries uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NotNull BuilderForAuthentication setHMACGetSecret(@Nullable HMACGetSecretOutput hmacGetSecret) {
            this.hmacGetSecret = hmacGetSecret;
            return this;
        }

        public @NotNull BuilderForAuthentication set(@NotNull String key, @Nullable Object value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }


    }

}
