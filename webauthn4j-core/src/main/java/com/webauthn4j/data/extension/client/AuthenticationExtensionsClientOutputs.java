package com.webauthn4j.data.extension.client;


import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.Serializable;
import java.util.*;

/**
 * Map containing the client extension output values for zero or more WebAuthn
 * extensions, as defined in §9 WebAuthn Extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-authenticationextensionsclientoutputs">§5.8. Authentication Extensions Client Outputs</a>
 */
public class AuthenticationExtensionsClientOutputs<T extends ExtensionClientOutput> implements Serializable {

    @JsonIgnore
    private final Map<String, Serializable> unknowns = new HashMap<>();
    @JsonProperty
    private Boolean appid;
    //appidExclude doesn't exist in ExtensionsClientOutputs
    @JsonProperty
    private UvmEntries uvm;
    @JsonProperty
    private CredentialPropertiesOutput credProps;
    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    @JsonAnySetter
    private void setUnknowns(@NonNull String name, @Nullable Serializable value) {
        this.unknowns.put(name, value);
    }

    @JsonAnyGetter
    private @NonNull Map<String, Serializable> getUnknowns() {
        return this.unknowns;
    }

    @JsonIgnore
    public @NonNull Set<String> getKeys() {
        Set<String> keys = new HashSet<>();
        if (appid != null) {
            keys.add("appid");
        }
        if (uvm != null) {
            keys.add("uvm");
        }
        if (credProps != null) {
            keys.add("credProps");
        }
        keys.addAll(getUnknownKeys());
        return keys;
    }

    @JsonIgnore
    public @NonNull Set<String> getUnknownKeys() {
        return unknowns.keySet();
    }

    @JsonIgnore
    public @Nullable Serializable getValue(@NonNull String key) {
        switch (key) {
            case "appid":
                return appid;
            case "uvm":
                return uvm;
            case "credProps":
                return credProps;
            default:
                return unknowns.get(key);
        }
    }

    @JsonIgnore
    public @Nullable Boolean getAppid() {
        return this.appid;
    }

    @JsonIgnore
    public @Nullable UvmEntries getUvm() {
        return this.uvm;
    }

    @JsonIgnore
    public @Nullable CredentialPropertiesOutput getCredProps() {
        return this.credProps;
    }

    @SuppressWarnings("unchecked")
    public @Nullable <E extends T> E getExtension(@NonNull Class<E> tClass) {
        return (E) getExtensions().get(tClass);
    }

    @SuppressWarnings("unchecked")
    @JsonIgnore
    public @NonNull Map<Class<? extends T>, T> getExtensions() {
        if (extensions == null) {
            Map<Class<? extends T>, T> map = new HashMap<>();
            if (appid != null) {
                map.put((Class<? extends T>) FIDOAppIDExtensionClientOutput.class, (T) new FIDOAppIDExtensionClientOutput(appid));
            }
            if (uvm != null) {
                map.put((Class<? extends T>) UserVerificationMethodExtensionClientOutput.class, (T) new UserVerificationMethodExtensionClientOutput(uvm));
            }
            if (credProps != null) {
                map.put((Class<? extends T>) CredentialPropertiesExtensionClientOutput.class, (T) new CredentialPropertiesExtensionClientOutput(credProps));
            }
            extensions = Collections.unmodifiableMap(map);
        }
        return extensions;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsClientOutputs<?> that = (AuthenticationExtensionsClientOutputs<?>) o;
        return Objects.equals(appid, that.appid) &&
                Objects.equals(uvm, that.uvm) &&
                Objects.equals(credProps, that.credProps) &&
                Objects.equals(unknowns, that.unknowns);
    }

    @Override
    public int hashCode() {
        return Objects.hash(appid, uvm, credProps, unknowns);
    }

    public static class BuilderForRegistration {

        private final Map<String, Serializable> unknowns = new HashMap<>();
        private UvmEntries uvm;
        private CredentialPropertiesOutput credProps;

        public @NonNull AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> build() {
            AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> instance = new AuthenticationExtensionsClientOutputs<>();
            instance.uvm = this.uvm;
            instance.credProps = this.credProps;
            instance.unknowns.putAll(this.unknowns);

            return instance;
        }

        public @NonNull BuilderForRegistration setUvm(@Nullable UvmEntries uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NonNull BuilderForRegistration setCredProps(@Nullable CredentialPropertiesOutput credProps) {
            this.credProps = credProps;
            return this;
        }


        public @NonNull BuilderForRegistration set(@NonNull String key, @Nullable Serializable value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }

    }

    public static class BuilderForAuthentication {

        private final Map<String, Serializable> unknowns = new HashMap<>();
        private Boolean appid;
        private UvmEntries uvm;

        public @NonNull AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> build() {
            AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> instance = new AuthenticationExtensionsClientOutputs<>();
            instance.appid = this.appid;
            instance.uvm = this.uvm;
            instance.unknowns.putAll(this.unknowns);

            return instance;
        }

        public @NonNull BuilderForAuthentication setAppid(@Nullable Boolean appid) {
            this.appid = appid;
            return this;
        }

        public @NonNull BuilderForAuthentication setUvm(@Nullable UvmEntries uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NonNull BuilderForAuthentication set(@NonNull String key, @Nullable Serializable value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }


    }

}
