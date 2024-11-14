/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

description = "WebAuthn4J Metadata Async library"

dependencies {
    api(project(":webauthn4j-core-async"))
    api(project(":webauthn4j-metadata"))

    implementation(libs.slf4j.api)

    //CompileOnly
    compileOnly(libs.jetbrains.annotations)

    //Test
    testImplementation(platform(libs.spring.boot.bom))

    testImplementation(project(":webauthn4j-test"))

    testImplementation("ch.qos.logback:logback-classic")
    testImplementation("org.projectlombok:lombok")
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.assertj:assertj-core")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testCompileOnly(libs.jetbrains.annotations)

}
