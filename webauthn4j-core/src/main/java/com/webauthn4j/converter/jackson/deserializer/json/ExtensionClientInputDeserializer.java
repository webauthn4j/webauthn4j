package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.ExtensionClientInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.util.Set;

/**
 * Base deserializer for {@link ExtensionClientInput} subtypes.
 * <p>
 * Each subclass extracts its extension's JSON key(s) from the raw JSON
 * and converts them into a typed extension input object. Registered in a Jackson Module
 * via {@code addDeserializer()}.
 *
 * @param <T> the type of extension input this deserializer produces
 */
public abstract class ExtensionClientInputDeserializer<T extends ExtensionClientInput> extends StdDeserializer<T> {

    protected ExtensionClientInputDeserializer(Class<T> type) {
        super(type);
    }

    /**
     * Returns the JSON key(s) that this deserializer consumes from the raw data.
     */
    public abstract @NotNull Set<String> getKeys();
}
