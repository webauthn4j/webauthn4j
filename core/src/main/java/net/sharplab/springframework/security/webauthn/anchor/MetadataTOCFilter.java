package net.sharplab.springframework.security.webauthn.anchor;

import net.sharplab.springframework.security.fido.metadata.structure.MetadataTOCPayloadEntry;

import java.util.function.Predicate;

/**
 * A functional interface for representing MetaDataTOC filtering logic.
 */
@SuppressWarnings("WeakerAccess")
public interface MetadataTOCFilter extends Predicate<MetadataTOCPayloadEntry> {
}
