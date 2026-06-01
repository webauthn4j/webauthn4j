package com.webauthn4j.converter.jackson;

import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.cfg.MapperConfig;
import tools.jackson.databind.introspect.Annotated;
import tools.jackson.databind.introspect.JacksonAnnotationIntrospector;

public class WebAuthnModuleGuardAnnotationIntrospector extends JacksonAnnotationIntrospector {

    @Override
    public Object findSerializer(MapperConfig<?> config, Annotated a) {
        Object ser = super.findSerializer(config, a);
        if (ser == ModuleNotRegisteredGuardSerializer.class) {
            return ValueSerializer.None.class;
        }
        return ser;
    }

    @Override
    public Object findDeserializer(MapperConfig<?> config, Annotated a) {
        Object deser = super.findDeserializer(config, a);
        if (deser == ModuleNotRegisteredGuardDeserializer.class) {
            return ValueDeserializer.None.class;
        }
        return deser;
    }
}
