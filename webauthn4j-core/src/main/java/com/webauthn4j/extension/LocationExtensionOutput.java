package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Objects;

public class LocationExtensionOutput extends AbstractExtensionOutput<LocationExtensionOutput.Coordinates> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("loc");

    @JsonCreator
    public LocationExtensionOutput(Coordinates value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }


    public static class Coordinates {

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

        public Coordinates(){}

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

}
