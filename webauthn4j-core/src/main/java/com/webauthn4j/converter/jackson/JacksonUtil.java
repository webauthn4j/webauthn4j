package com.webauthn4j.converter.jackson;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.exc.MismatchedInputException;

public class JacksonUtil {

    private static final String INPUT_MISMATCH_ERROR_MESSAGE = "Input data does not match expected form";

    private JacksonUtil() {
    }

    public static @NotNull JsonNode readTree(@NotNull ObjectMapper objectMapper, @NotNull byte[] bytes) {
        AssertUtil.notNull(objectMapper, "objectMapper must not be null");
        AssertUtil.notNull(bytes, "bytes must not be null");

        try {
            return objectMapper.readTree(bytes);
        } catch (MismatchedInputException | StreamReadException e) {
            throw new DataConversionException(INPUT_MISMATCH_ERROR_MESSAGE, e);
        }
    }

    public static @Nullable byte[] binaryValue(@Nullable JsonNode jsonNode) {
        return jsonNode == null ? null : jsonNode.binaryValue();
    }

}
