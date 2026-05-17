package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.util.Set;

/**
 * Base deserializer for {@link ExtensionAuthenticatorOutput} subtypes.
 * <p>
 * Each subclass extracts its extension's CBOR key(s) from the raw data
 * and converts them into a typed extension output object. Registered in a Jackson Module
 * via {@code addDeserializer()}.
 *
 * @param <T> the type of extension output this deserializer produces
 */
public abstract class ExtensionAuthenticatorOutputDeserializer<T extends ExtensionAuthenticatorOutput> extends StdDeserializer<T> {

    protected ExtensionAuthenticatorOutputDeserializer(Class<T> type) {
        super(type);
    }

    /**
     * Returns the CBOR key(s) that this deserializer consumes from the raw data.
     */
    public abstract @NotNull Set<String> getKeys();
}
