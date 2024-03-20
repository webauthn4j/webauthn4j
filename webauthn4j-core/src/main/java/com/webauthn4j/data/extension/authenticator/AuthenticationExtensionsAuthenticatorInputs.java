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
import com.webauthn4j.converter.jackson.deserializer.cbor.HMACSecretAuthenticatorInputDeserializer;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.*;
import java.util.stream.Collectors;


/**
 * {@link AuthenticationExtensionsAuthenticatorInputs} containing the authenticator extension input values for
 * zero or more WebAuthn extensions, as defined in §9 WebAuthn Extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#typedefdef-authenticationextensionsauthenticatorinputs">
 * §5.9. Authentication Extensions Authenticator Inputs (typedef AuthenticationExtensionsAuthenticatorInputs)</a>
 */
public class AuthenticationExtensionsAuthenticatorInputs<T extends ExtensionAuthenticatorInput> {

    private static final String KEY_UVM = "uvm";
    private static final String KEY_CRED_PROTECT = "credProtect";
    private static final String KEY_HMAC_SECRET = "hmac-secret";

    @JsonIgnore
    private final Map<String, Object> unknowns = new HashMap<>();
    @JsonProperty
    private Boolean uvm;
    @JsonProperty
    private CredentialProtectionPolicy credProtect;
    @JsonIgnore
    private Boolean hmacCreateSecret;
    @JsonIgnore
    private HMACGetSecretAuthenticatorInput hmacGetSecret;
    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    @JsonSetter(KEY_HMAC_SECRET)
    @JsonDeserialize(using = HMACSecretAuthenticatorInputDeserializer.class)
    private void setHMACSecret(Object hmacSecret){
        if(hmacSecret instanceof Boolean){
            hmacCreateSecret = (Boolean)hmacSecret;
            hmacGetSecret = null;
        }
        else {
            hmacCreateSecret = null;
            hmacGetSecret = (HMACGetSecretAuthenticatorInput)hmacSecret;
        }
    }

    @JsonAnyGetter
    private Map<String, Object> getUnknowns() {
        return Collections.unmodifiableMap(this.unknowns);
    }

    @JsonAnySetter
    private void setUnknowns(@NonNull String name, @Nullable Object value) {
        this.unknowns.put(name, value);
    }

    @JsonIgnore
    public @NonNull Set<String> getKeys() {
        Set<String> keys = new HashSet<>();
        if (uvm != null) {
            keys.add(KEY_UVM);
        }
        if (credProtect != null) {
            keys.add(KEY_CRED_PROTECT);
        }
        if(hmacCreateSecret != null){
            keys.add(KEY_HMAC_SECRET);
        }
        if(hmacGetSecret != null){
            keys.add(KEY_HMAC_SECRET);
        }
        keys.addAll(getUnknownKeys());
        return keys;
    }

    @JsonIgnore
    public @NonNull Set<String> getUnknownKeys() {
        return unknowns.keySet();
    }

    @JsonIgnore
    public @Nullable Object getValue(String key) {
        switch (key) {
            case KEY_UVM:
                return uvm;
            case KEY_CRED_PROTECT:
                return credProtect;
            case KEY_HMAC_SECRET:
                return hmacCreateSecret != null ? hmacCreateSecret : hmacGetSecret;
            default:
                return unknowns.get(key);
        }
    }

    @JsonIgnore
    public @Nullable Boolean getUvm() {
        return this.uvm;
    }

    @JsonIgnore
    public @Nullable CredentialProtectionPolicy getCredProtect() {
        return this.credProtect;
    }

    @JsonGetter(KEY_HMAC_SECRET)
    public @Nullable Object getHMACSecret(){
        return hmacCreateSecret != null ? hmacCreateSecret : hmacGetSecret;
    }

    @JsonIgnore
    public @Nullable Boolean getHMACCreateSecret() {
        return hmacCreateSecret;
    }

    @JsonIgnore
    public @Nullable HMACGetSecretAuthenticatorInput getHMACGetSecret() {
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
                map.put((Class<? extends T>) UserVerificationMethodExtensionAuthenticatorInput.class, (T) new UserVerificationMethodExtensionAuthenticatorInput(uvm));
            }
            if (credProtect != null) {
                map.put((Class<? extends T>) CredentialProtectionExtensionAuthenticatorInput.class, (T) new CredentialProtectionExtensionAuthenticatorInput(credProtect));
            }
            if (hmacCreateSecret != null) {
                map.put((Class<? extends T>) HMACSecretRegistrationExtensionAuthenticatorInput.class, (T) new HMACSecretRegistrationExtensionAuthenticatorInput(hmacCreateSecret));
            }
            if (hmacGetSecret != null) {
                map.put((Class<? extends T>) HMACSecretAuthenticationExtensionAuthenticatorInput.class, (T) new HMACSecretAuthenticationExtensionAuthenticatorInput(hmacGetSecret));
            }
            extensions = Collections.unmodifiableMap(map);
        }
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsAuthenticatorInputs<?> that = (AuthenticationExtensionsAuthenticatorInputs<?>) o;
        return Objects.equals(unknowns, that.unknowns) && Objects.equals(uvm, that.uvm) && credProtect == that.credProtect && Objects.equals(hmacCreateSecret, that.hmacCreateSecret) && Objects.equals(hmacGetSecret, that.hmacGetSecret) && Objects.equals(extensions, that.extensions);
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

    @Override
    public int hashCode() {
        return Objects.hash(unknowns, uvm, credProtect, hmacCreateSecret, hmacGetSecret, extensions);
    }

    public static class BuilderForRegistration {

        private final Map<String, Object> unknowns = new HashMap<>();
        private Boolean uvm;
        private CredentialProtectionPolicy credProtect;
        private Boolean hmacCreateSecret;

        public @NonNull AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> build() {
            AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> instance = new AuthenticationExtensionsAuthenticatorInputs<>();
            instance.uvm = this.uvm;
            instance.credProtect = this.credProtect;
            instance.hmacCreateSecret = this.hmacCreateSecret;
            instance.unknowns.putAll(this.unknowns);

            return instance;
        }

        public @NonNull BuilderForRegistration setUvm(@Nullable Boolean uvm) {
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

        public @NonNull BuilderForRegistration set(@NonNull String key, @Nullable Object value) {
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }

    }

    public static class BuilderForAuthentication {

        private final Map<String, Object> unknowns = new HashMap<>();
        private Boolean uvm;
        private HMACGetSecretAuthenticatorInput hmacGetSecret;

        public @NonNull AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> build() {
            AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> instance = new AuthenticationExtensionsAuthenticatorInputs<>();
            instance.uvm = this.uvm;
            instance.hmacGetSecret = this.hmacGetSecret;
            instance.unknowns.putAll(this.unknowns);

            return instance;
        }

        public @NonNull BuilderForAuthentication setUvm(@Nullable Boolean uvm) {
            this.uvm = uvm;
            return this;
        }

        public @NonNull BuilderForAuthentication setHMACGetSecret(@Nullable HMACGetSecretAuthenticatorInput hmacGetSecret) {
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