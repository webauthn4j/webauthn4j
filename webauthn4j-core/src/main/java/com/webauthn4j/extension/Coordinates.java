/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.extension;

import java.io.Serializable;
import java.util.Objects;

public class Coordinates implements Serializable {

    private Double latitude;
    private Double longitude;
    private Double altitude;
    private Double accuracy;
    private Double altitudeAccuracy;
    private Double heading;
    private Double speed;

    public Coordinates(Double latitude, Double longitude, Double altitude, Double accuracy, Double altitudeAccuracy, Double heading, Double speed) {
        this.latitude = latitude;
        this.longitude = longitude;
        this.altitude = altitude;
        this.accuracy = accuracy;
        this.altitudeAccuracy = altitudeAccuracy;
        this.heading = heading;
        this.speed = speed;
    }

    public Coordinates() {
    }

    public Double getLatitude() {
        return latitude;
    }

    public Double getLongitude() {
        return longitude;
    }

    public Double getAltitude() {
        return altitude;
    }

    public Double getAccuracy() {
        return accuracy;
    }

    public Double getAltitudeAccuracy() {
        return altitudeAccuracy;
    }

    public Double getHeading() {
        return heading;
    }

    public Double getSpeed() {
        return speed;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Coordinates that = (Coordinates) o;
        return Objects.equals(latitude, that.latitude) &&
                Objects.equals(longitude, that.longitude) &&
                Objects.equals(altitude, that.altitude) &&
                Objects.equals(accuracy, that.accuracy) &&
                Objects.equals(altitudeAccuracy, that.altitudeAccuracy) &&
                Objects.equals(heading, that.heading) &&
                Objects.equals(speed, that.speed);
    }

    @Override
    public int hashCode() {

        return Objects.hash(latitude, longitude, altitude, accuracy, altitudeAccuracy, heading, speed);
    }
}
