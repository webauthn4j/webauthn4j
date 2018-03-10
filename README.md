# Spring Security WebAuthn

Spring Security WebAuthn provides Web Authentication specification support for your Spring application.
Users can login with WebAuthn compliant authenticator.

## Documentation

You can find out more details from the [reference](http://) or by browsing the [javadoc](http://).

## Build

Spring Security WebAuthn uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java8

### Checkout sources

```
git clone <source repository>
```

### Compile and test; build all jars; distribution zips; and docs

```
./gradlew build
```

## Sample

```
./gradlew spring-security-webauthn-sample:bootRun
```

## License

Spring Security WebAuthn is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
