package com.webauthn4j.extension;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class CoordinatesTest {

    @Test
    public void getter_test() {
        Coordinates instance = new Coordinates(
                12.34,
                23.45,
                34.56,
                4.5,
                5.6,
                7.8,
                8.9
        );

        assertThat(instance.getLatitude()).isEqualTo(12.34);
        assertThat(instance.getLongitude()).isEqualTo(23.45);
        assertThat(instance.getAltitude()).isEqualTo(34.56);
        assertThat(instance.getAccuracy()).isEqualTo(4.5);
        assertThat(instance.getAltitudeAccuracy()).isEqualTo(5.6);
        assertThat(instance.getHeading()).isEqualTo(7.8);
        assertThat(instance.getSpeed()).isEqualTo(8.9);
    }

    @Test
    public void equals_hashCode_test() {
        Coordinates instanceA = new Coordinates();
        Coordinates instanceB = new Coordinates();

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }
}
