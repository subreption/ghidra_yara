/* ###
 * IP: GHIDRA
 * Copyright (c) 2024 Subreption LLC. All rights reserved.
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
 *
 * ---
 * Created: Sep 22, 2024 (sbrptdev2)
 *
 */
package ghidra_yara;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 *
 */

public class DateTimeUtils
{
	// ISO-8601 formatter
	private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

	// Convert LocalDateTime to nanoseconds since the epoch
	public static long toEpochNanos(LocalDateTime dateTime) {
		return dateTime.toInstant(ZoneOffset.UTC).toEpochMilli() * 1_000_000 + dateTime.getNano();
	}

	// Convert LocalDateTime to milliseconds since the epoch (optional)
	public static long toEpochMillis(LocalDateTime dateTime) {
		return dateTime.toInstant(ZoneOffset.UTC).toEpochMilli();
	}

	// Convert nanoseconds since epoch back to LocalDateTime
	public static LocalDateTime fromEpochNanos(long epochNanos) {
		long millis = epochNanos / 1_000_000;
		int nanos = (int) (epochNanos % 1_000_000_000);
		return LocalDateTime.ofEpochSecond(millis / 1000, nanos, ZoneOffset.UTC);
	}

	// Convert milliseconds since epoch back to LocalDateTime
	public static LocalDateTime fromEpochMillis(long epochMillis) {
		return LocalDateTime.ofEpochSecond(epochMillis / 1000, (int) (epochMillis % 1000) * 1_000_000, ZoneOffset.UTC);
	}

	// Convert LocalDateTime to ISO-8601 string
	public static String toIsoString(LocalDateTime dateTime) {
		return dateTime.format(ISO_FORMATTER);
	}

	// Convert ISO-8601 string back to LocalDateTime
	public static LocalDateTime fromIsoString(String isoString) {
		return LocalDateTime.parse(isoString, ISO_FORMATTER);
	}
}
