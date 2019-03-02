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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * This descriptor contains description in alternative languages.
 */
public class AlternativeDescriptions extends AbstractMap<String, String> {
	
	private final Map<String, String> alternativeDescription;
	
	@JsonCreator
	public AlternativeDescriptions(
		Map<String, String> alternativeDescription) {
		this.alternativeDescription = alternativeDescription;
	}
	
	public AlternativeDescriptions(){
		this(Collections.emptyMap());
	}
	
	@Override
	public Set<Entry<String, String>> entrySet() {
		return alternativeDescription.entrySet();
	}
	
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		if (!super.equals(o)) {
			return false;
		}
		AlternativeDescriptions that = (AlternativeDescriptions) o;
		return Objects.equals(alternativeDescription, that.alternativeDescription);
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), alternativeDescription);
	}
}
