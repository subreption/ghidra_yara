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

import java.util.Base64;


/**
 *
 */
public class ByteArrayUtils
{
	// Encode byte[] into a Base64 string
	public static String encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	// Decode a Base64 string back into byte[]
	public static byte[] decode(String base64String) {
		return Base64.getDecoder().decode(base64String);
	}
}
