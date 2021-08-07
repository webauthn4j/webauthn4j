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

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.converter.jackson.deserializer.CredentialProtectionPolicyByteDeserializer;
import com.webauthn4j.converter.jackson.serializer.CredentialProtectionPolicyByteSerializer;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.Serializable;
import java.util.*;

public class AuthenticationExtensionsAuthenticatorOutputs<T extends ExtensionAuthenticatorOutput> implements Serializable {

    @JsonIgnore
    private final Map<String, Serializable> unknowns = new HashMap<>();
    @JsonProperty
    private UvmEntries uvm;
    @JsonSerialize(using = CredentialProtectionPolicyByteSerializer.class)
    @JsonDeserialize(using = CredentialProtectionPolicyByteDeserializer.class)
    @JsonProperty
    private CredentialProtectionPolicy credProtect;
    @JsonIgnore
    private Boolean hmacCreateSecret;
    @JsonIgnore
    private byte[] hmacGetSecret;
    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    @JsonSetter("hmac-secret")
    private void setHMACSecret(Object hmacSecret){
        if(hmacSecret instanceof Boolean){
            hmacCreateSecret = (Boolean)hmacSecret;
            hmacGetSecret = null;
        }
        else {
            hmacCreateSecret = null;
            hmacGetSecret = (byte[])hmacSecret;
        }
    }

    @JsonGetter("hmac-secret")
    private Object getHMACSecret(){
        return hmacCreateSecret != null ? hmacCreateSecret : hmacGetSecret;
    }

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
        if (uvm != null) {
            keys.add("uvm");
        }
        if (credProtect != null) {
            keys.add("credProtect");
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
            case "uvm":
                return uvm;
            case "credProtect":
                return credProtect;
            case "hmacCreateSecret":
                return hmacCreateSecret;
            case "hmacGetSecret":
                return hmacGetSecret;
            default:
                return unknowns.get(key);
        }
    }

    @JsonIgnore
    public @Nullable UvmEntries getUvm() {
        return this.uvm;
    }

    @JsonIgnore
    public @Nullable CredentialProtectionPolicy getCredProtect() {
        return credProtect;
    }

    @JsonIgnore
    public @Nullable Boolean getHmacCreateSecret() {
        return hmacCreateSecret;
    }

    @JsonIgnore
    public @Nullable byte[] getHmacGetSecret() {
        return hmacGetSecret;
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
            if (uvm != null) {
                map.put((Class<? extends T>) UserVerificationMethodExtensionAuthenticatorOutput.class, (T) new UserVerificationMethodExtensionAuthenticatorOutput(uvm));
            }
            if (credProtect != null) {
                map.put((Class<? extends T>) CredentialProtectionExtensionAuthenticatorOutput.class, (T) new CredentialProtectionExtensionAuthenticatorOutput(credProtect));
            }
            if (hmacCreateSecret != null) {
                map.put((Class<? extends T>) HMACSecretRegistrationExtensionAuthenticatorOutput.class, (T) new HMACSecretRegistrationExtensionAuthenticatorOutput(hmacCreateSecret));
            }
            if (hmacGetSecret != null) {
                map.put((Class<? extends T>) HMACSecretAuthenticationExtensionAuthenticatorOutput.class, (T) new HMACSecretAuthenticationExtensionAuthenticatorOutput(hmacGetSecret));
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
        return Objects.equals(unknowns, that.unknowns) && Objects.equals(uvm, that.uvm) && credProtect == that.credProtect && Objects.equals(hmacCreateSecret, that.hmacCreateSecret) && Arrays.equals(hmacGetSecret, that.hmacGetSecret) && Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(unknowns, uvm, credProtect, hmacCreateSecret, extensions);
        result = 31 * result + Arrays.hashCode(hmacGetSecret);
        return result;
    }

    public static class BuilderForRegistration {

        private final Map<String, Serializable> unknowns = new HashMap<>();
        private UvmEntries uvm;
        private CredentialProtectionPolicy credProtect;
        private Boolean hmacCreateSecret;

        public @NonNull AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> build() {
            AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> instance = new AuthenticationExtensionsAuthenticatorOutputs<>();
            instance.uvm = this.uvm;
            instance.credProtect = this.credProtect;
            instance.unknowns.putAll(this.unknowns);
            instance.hmacCreateSecret = this.hmacCreateSecret;

            return instance;
        }

        public @NonNull BuilderForRegistration setUvm(@Nullable UvmEntries uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NonNull BuilderForRegistration setCredProtect(@Nullable CredentialProtectionPolicy credProtect) {
            this.credProtect = credProtect;
            return this;
        }

        public @NonNull BuilderForRegistration setHMACCreateSecret(@Nullable Boolean hmacCreateSecret) {
            this.hmacCreateSecret = hmacCreateSecret;
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
        private UvmEntries uvm;
        private byte[] hmacGetSecret;

        public @NonNull AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> build() {
            AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> instance = new AuthenticationExtensionsAuthenticatorOutputs<>();
            instance.uvm = this.uvm;
            instance.unknowns.putAll(this.unknowns);
            instance.hmacGetSecret = this.hmacGetSecret;

            return instance;
        }

        public @NonNull BuilderForAuthentication setUvm(@Nullable UvmEntries uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NonNull BuilderForAuthentication setHMACGetSecret(@Nullable byte[] hmacGetSecret) {
            this.hmacGetSecret = hmacGetSecret;
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
