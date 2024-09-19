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
