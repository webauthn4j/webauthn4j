package com.webauthn4j.converter.jackson;

import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.cfg.MapperBuilder;

@JsonSerialize(using = ValueSerializer.None.class)
@JsonDeserialize(using = ValueDeserializer.None.class)
public interface ModuleNotRegisteredGuardClearingMixin {

    public static void setIfAbsent(@NotNull JacksonModule.SetupContext context, @NotNull Class<?> type) {
        MapperBuilder<?, ?> builder = (MapperBuilder<?, ?>) context.getOwner();
        if (builder.mixInHandler().findMixInClassFor(type) == null) {
            context.setMixIn(type, ModuleNotRegisteredGuardClearingMixin.class);
        }
    }
}
