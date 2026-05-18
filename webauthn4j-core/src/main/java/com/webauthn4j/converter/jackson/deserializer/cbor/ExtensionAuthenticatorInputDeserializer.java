package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.util.Set;

/**
 * Base deserializer for {@link ExtensionAuthenticatorInput} subtypes.
 * <p>
 * Each subclass extracts its extension's CBOR key(s) from the raw data
 * and converts them into a typed extension input object. Registered in a Jackson Module
 * via {@code addDeserializer()}.
 *
 * @param <T> the type of extension input this deserializer produces
 */
public abstract class ExtensionAuthenticatorInputDeserializer<T extends ExtensionAuthenticatorInput> extends StdDeserializer<T> {

    protected ExtensionAuthenticatorInputDeserializer(Class<T> type) {
        super(type);
    }

    /**
     * Returns the CBOR key(s) that this deserializer consumes from the raw data.
     */
    public abstract @NotNull Set<String> getKeys();
}
