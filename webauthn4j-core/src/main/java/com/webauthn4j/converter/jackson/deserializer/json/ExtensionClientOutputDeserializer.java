package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.util.Set;

/**
 * Base deserializer for {@link ExtensionClientOutput} subtypes.
 * <p>
 * Each subclass extracts its extension's JSON key(s) from the raw JSON
 * and converts them into a typed extension output object. Registered in a Jackson Module
 * via {@code addDeserializer()}.
 *
 * @param <T> the type of extension output this deserializer produces
 */
public abstract class ExtensionClientOutputDeserializer<T extends ExtensionClientOutput> extends StdDeserializer<T> {

    protected ExtensionClientOutputDeserializer(Class<T> type) {
        super(type);
    }

    /**
     * Returns the JSON key(s) that this deserializer consumes from the raw data.
     */
    public abstract @NotNull Set<String> getKeys();
}
