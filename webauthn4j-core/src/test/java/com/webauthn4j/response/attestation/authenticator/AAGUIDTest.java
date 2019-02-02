package com.webauthn4j.response.attestation.authenticator;

import com.webauthn4j.util.UUIDUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AAGUIDTest {

    @Test
    public void constructor_for_string_test(){
        AAGUID aaguid = new AAGUID("f1ff13a4-2e00-4984-97e2-def33de3ddf8");
        assertThat(aaguid).isNotNull();
        AAGUID aaguidFromNull = new AAGUID((String)null);
        assertThat(aaguidFromNull).isNotNull();
        assertThat(aaguidFromNull).isEqualTo(AAGUID.NULL);
    }

    @Test
    public void constructor_for_bytes_test(){
        AAGUID aaguid = new AAGUID(new byte[16]);
        assertThat(aaguid).isNotNull();
        AAGUID aaguidFromNull = new AAGUID((String)null);
        assertThat(aaguidFromNull).isNotNull();
        assertThat(aaguidFromNull).isEqualTo(AAGUID.NULL);
    }

    @Test
    public void getValue_test(){
        assertThat(AAGUID.ZERO.getValue()).isEqualTo(UUIDUtil.fromBytes(new byte[16]));
    }

    @Test
    public void equals_hashCode_test(){
        AAGUID instanceA = new AAGUID("f1ff13a4-2e00-4984-97e2-def33de3ddf8");
        AAGUID instanceB = new AAGUID("f1ff13a4-2e00-4984-97e2-def33de3ddf8");

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);

    }

}