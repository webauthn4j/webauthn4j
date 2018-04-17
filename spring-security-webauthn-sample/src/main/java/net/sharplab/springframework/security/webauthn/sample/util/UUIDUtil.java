package net.sharplab.springframework.security.webauthn.sample.util;

import java.nio.ByteBuffer;
import java.util.UUID;

public class UUIDUtil {

    private UUIDUtil() {
    }

    public static byte[] toByteArray(UUID uuid) {
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        return ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
    }
}
