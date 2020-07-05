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

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.util.AssertUtil;

import java.io.Serializable;
import java.util.*;

public class AuthenticationExtensionsAuthenticatorOutputs<T extends ExtensionAuthenticatorOutput> implements Serializable {

    @JsonProperty
    private UvmEntries uvm;
    @JsonIgnore
    private Map<String, Serializable> unknowns = new HashMap<>();
    @JsonIgnore
    private Map<Class<? extends T>, T> extensions;

    @JsonAnySetter
    private void setUnknowns(String name, Serializable value){
        this.unknowns.put(name, value);
    }

    @JsonAnyGetter
    private Map<String, Serializable> getUnknowns(){
        return this.unknowns;
    }

    @JsonIgnore
    public Set<String> getKeys() {
        Set<String> keys = new HashSet<>();
        if(uvm != null){
            keys.add("uvm");
        }
        keys.addAll(getUnknownKeys());
        return keys;
    }

    @JsonIgnore
    public Set<String> getUnknownKeys() {
        return unknowns.keySet();
    }

    @SuppressWarnings({"SwitchStatementWithTooFewBranches", "java:S1301"})
    @JsonIgnore
    public Object getValue(String key) {
        switch (key){
            case "uvm":
                return uvm;
            default:
                return unknowns.get(key);
        }
    }

    @JsonIgnore
    public UvmEntries getUvm(){
        return this.uvm;
    }

    @SuppressWarnings("unchecked")
    public <E extends T> E getExtension(Class<E> tClass) {
        return (E)getExtensions().get(tClass);
    }

    @SuppressWarnings("unchecked")
    @JsonIgnore
    public Map<Class<? extends T>, T> getExtensions(){
        if(extensions == null){
            Map<Class<? extends T>, T> map = new HashMap<>();
            if(uvm != null){
                map.put((Class<? extends T>)UserVerificationMethodExtensionAuthenticatorOutput.class, (T)new UserVerificationMethodExtensionAuthenticatorOutput(uvm));
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
        return Objects.equals(uvm, that.uvm) &&
                Objects.equals(unknowns, that.unknowns);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uvm, unknowns);
    }

    public static class BuilderForRegistration {

        private UvmEntries uvm;

        private Map<String, Serializable> unknowns = new HashMap<>();

        public AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> build(){
            AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> instance = new AuthenticationExtensionsAuthenticatorOutputs<>();
            instance.uvm = this.uvm;
            instance.unknowns = this.unknowns;

            return instance;
        }

        public BuilderForRegistration setUvm(UvmEntries uvm){
            this.uvm = uvm;
            return this;
        }

        public BuilderForRegistration set(String key, Serializable value){
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }

    }

    public static class BuilderForAuthentication {

        private UvmEntries uvm;

        private Map<String, Serializable> unknowns = new HashMap<>();


        public AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> build(){
            AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> instance = new AuthenticationExtensionsAuthenticatorOutputs<>();
            instance.uvm = this.uvm;
            instance.unknowns = this.unknowns;

            return instance;
        }

        public BuilderForAuthentication setUvm(UvmEntries uvm){
            this.uvm = uvm;
            return this;
        }

        public BuilderForAuthentication set(String key, Serializable value){
            AssertUtil.notNull(key, "key must not be null.");
            AssertUtil.notNull(value, "value must not be null.");
            unknowns.put(key, value);
            return this;
        }


    }

}
