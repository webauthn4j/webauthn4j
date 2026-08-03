package com.webauthn4j.gradle.agent;

import java.lang.instrument.Instrumentation;
import java.security.Provider;
import java.security.Security;
import java.util.Set;

public class SecurityProviderAgent {

    public static void premain(String args, Instrumentation inst) {
        String providerList = System.getProperty("webauthn4j.test.securityProviders");
        if (providerList == null) {
            return;
        }

        Set<String> keepClasses = Set.of(providerList.split(","));
        for (Provider p : Security.getProviders()) {
            if (!keepClasses.contains(p.getClass().getName())) {
                Security.removeProvider(p.getName());
            }
        }

        String prefix = "webauthn4j.test.security.";
        for (String key : System.getProperties().stringPropertyNames()) {
            if (key.startsWith(prefix)) {
                String securityKey = key.substring(prefix.length());
                Security.setProperty(securityKey, System.getProperty(key));
            }
        }
    }
}
