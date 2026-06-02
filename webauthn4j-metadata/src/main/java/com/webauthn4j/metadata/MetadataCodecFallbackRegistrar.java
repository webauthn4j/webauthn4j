package com.webauthn4j.metadata;

import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardClearingMixin;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardDeserializer;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardSerializer;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.deserializer.AAIDDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.AuthenticatorStatusDeserializer;
import com.webauthn4j.metadata.converter.jackson.deserializer.MetadataAAGUIDRelaxedDeserializer;
import com.webauthn4j.metadata.converter.jackson.serializer.AAIDSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.AuthenticatorStatusSerializer;
import com.webauthn4j.metadata.converter.jackson.serializer.MetadataAAGUIDSerializer;
import com.webauthn4j.metadata.data.toc.AuthenticatorStatus;
import com.webauthn4j.metadata.data.uaf.AAID;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.std.StdSerializer;

public class MetadataCodecFallbackRegistrar {

    private static final Logger logger = LoggerFactory.getLogger(MetadataCodecFallbackRegistrar.class);

    private MetadataCodecFallbackRegistrar() {}

    public static @NotNull ObjectConverter registerFallbackMetadataCodecsIfNeeded(@NotNull ObjectConverter objectConverter) {
        SimpleModule fallback = new SimpleModule("WebAuthnMetadataFallbackModule") {
            @Override
            public void setupModule(SetupContext context) {
                super.setupModule(context);
                ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, AAID.class);
                ModuleNotRegisteredGuardClearingMixin.setIfAbsent(context, AuthenticatorStatus.class);
            }
        };
        boolean needsFallback = false;

        needsFallback |= addSerializerIfGuard(objectConverter, fallback, AAID.class, new AAIDSerializer());
        needsFallback |= addDeserializerIfGuard(objectConverter, fallback, AAID.class, new AAIDDeserializer());
        needsFallback |= addSerializerIfGuard(objectConverter, fallback, AuthenticatorStatus.class, new AuthenticatorStatusSerializer());
        needsFallback |= addDeserializerIfGuard(objectConverter, fallback, AuthenticatorStatus.class, new AuthenticatorStatusDeserializer());
        needsFallback |= addSerializerIfGuard(objectConverter, fallback, AAGUID.class, new MetadataAAGUIDSerializer());
        needsFallback |= addDeserializerIfGuard(objectConverter, fallback, AAGUID.class, new MetadataAAGUIDRelaxedDeserializer());

        if (needsFallback) {
            logger.warn("WebAuthnMetadataJSONModule is not registered. "
                    + "Registering default serializers/deserializers automatically. "
                    + "In a future release, explicit registration via "
                    + "ObjectConverter.rebuildWithJSONModule(new WebAuthnMetadataJSONModule()) will be required.");
            return objectConverter.rebuildWithJSONModule(fallback);
        }
        return objectConverter;
    }

    private static boolean isGuardSerializer(@NotNull ObjectConverter objectConverter, @NotNull Class<?> type) {
        return objectConverter.getJsonMapper()._serializationContext()
                .findValueSerializer(type) instanceof ModuleNotRegisteredGuardSerializer;
    }

    private static boolean isGuardDeserializer(@NotNull ObjectConverter objectConverter, @NotNull Class<?> type) {
        JavaType javaType = objectConverter.getJsonMapper().constructType(type);
        return objectConverter.getJsonMapper()._deserializationContext()
                .findRootValueDeserializer(javaType) instanceof ModuleNotRegisteredGuardDeserializer;
    }

    private static <T> boolean addSerializerIfGuard(@NotNull ObjectConverter objectConverter, @NotNull SimpleModule module, @NotNull Class<T> type, @NotNull StdSerializer<T> serializer) {
        if (isGuardSerializer(objectConverter, type)) {
            module.addSerializer(type, serializer);
            return true;
        }
        return false;
    }

    private static <T> boolean addDeserializerIfGuard(@NotNull ObjectConverter objectConverter, @NotNull SimpleModule module, @NotNull Class<T> type, @NotNull StdDeserializer<? extends T> deserializer) {
        if (isGuardDeserializer(objectConverter, type)) {
            module.addDeserializer(type, deserializer);
            return true;
        }
        return false;
    }
}
