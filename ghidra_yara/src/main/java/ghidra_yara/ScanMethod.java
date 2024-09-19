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
 */
package ghidra_yara;

public enum ScanMethod {
	/**
	 * An enumeration describing a Windows OS version by String and by ordinal.
	 * The most significant 1 or 2 digits of the ordinal specify the major Windows release.
	 * The least significant 4 digits provide the minor release.
	 */
		MONOLITHIC(0, "Monolithic"),
		BLOCK_BASED(1, "Block-based");

		private String display;
		private int order;

		ScanMethod(int ord, String disp) {
			display = disp;
			order = ord;
		}

		public int getOrder() {
			return order;
		}

		@Override
		public String toString() {
			return display;
		}
}
