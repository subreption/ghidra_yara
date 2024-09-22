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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

/**
 * GhidraYaraRule is a Saveable object leveraging Ghidra's object storage. This
 * allows smooth transitions within the different tools, and session
 * save/restore capabilities. TODO: We currently need to integrate this with the
 * ProgramDB.
 */
public class GhidraYaraRule implements Saveable {
	private static final int serialVersionUID = 1;

	public static String META_AUTHOR_NAME = "author";
	public static String META_DESCRIPTION_NAME = "description";

	private String ruleName;
	private String author;
	private String description;

	// Timestamps for creation and updates
	private LocalDateTime createdAt;
	private LocalDateTime updatedAt;

	private List<String> tags;
	private Map<String, String> meta;
	private List<byte[]> byteArrays;

	// SHA-256 for the target (coalesced) bytes
	private MessageDigest bytesDigest;
	private Boolean bytesDigestFinalized;

	private void initialize() {
		this.tags = new ArrayList<>();
		this.meta = new HashMap<>();
		this.byteArrays = new ArrayList<>();

		this.createdAt = LocalDateTime.now(); // Set creation timestamp
		this.updatedAt = LocalDateTime.now(); // Set initial update timestamp

		this.newBytesDigest();
	}

	public GhidraYaraRule() {
		// required for Saveables
	}

	public GhidraYaraRule(String ruleName) {
		this.ruleName = ruleName;
		initialize();
	}

	public GhidraYaraRule(byte[] bytes) {
		initialize();
		addByteArray(bytes);
	}

	// Constructor with ruleName and byte array
	public GhidraYaraRule(String ruleName, byte[] bytes) {
		this(ruleName);
		addByteArray(bytes);
		updateTimestamp();
	}

	public void addTag(String tag) {
		tags.add(tag);
		updateTimestamp();
	}

	// Update the updatedAt timestamp
	private void updateTimestamp() {
		this.updatedAt = LocalDateTime.now();
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
		meta.put(META_AUTHOR_NAME, author);
		updateTimestamp();
	}

	// Getter and Setter for Description
	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
		meta.put(META_DESCRIPTION_NAME, description);
		updateTimestamp();
	}

	public void setIdentifier(String identifier) {
		this.ruleName = identifier;
		updateTimestamp();
	}

	public void addMeta(String key, String value) {
		meta.put(key, value);
	}

	// Add a byte array (for use in the condition)
	public void addByteArray(byte[] bytes) {
		byteArrays.add(bytes);
		updateBytesDigest(bytes);
		updateTimestamp();
	}

	public String getTags() {
		return tags.toString();
	}

	// Generate the string representation of the YARA rule
	@Override
	public String toString() {
		StringBuilder yaraRule = new StringBuilder();

		if (ruleName == null || (ruleName != null && ruleName.isBlank())) {
			ruleName = generateHashBasedRuleName();
		}

		// Add rule name
		yaraRule.append("rule ").append(ruleName).append(" {\n");

		// Ensure the author and description are reflected in the meta map
		if (!author.isEmpty()) {
			meta.put(META_AUTHOR_NAME, author);
		}
		if (!description.isEmpty()) {
			meta.put(META_DESCRIPTION_NAME, description);
		}

		// Add tags
		if (!tags.isEmpty()) {
			yaraRule.append("  tags: ");
			for (String tag : tags) {
				yaraRule.append(tag).append(" ");
			}
			yaraRule.append("\n");
		}

		// Add metadata
		if (!meta.isEmpty()) {
			yaraRule.append("  meta:\n");
			for (Map.Entry<String, String> entry : meta.entrySet()) {
				yaraRule.append("    ").append(entry.getKey()).append(" = \"").append(entry.getValue()).append("\"\n");
			}
		}

		// Add strings (hex format for byte arrays)
		yaraRule.append("  strings:\n");
		for (int i = 0; i < byteArrays.size(); i++) {
			yaraRule.append("    $bytes" + i + " = { ");

			for (byte b : byteArrays.get(i)) {
				yaraRule.append(String.format("%02X ", b));
			}

			yaraRule.append("}\n");
		}

		yaraRule.append("  condition:\n");
		yaraRule.append("    any of them\n");

		yaraRule.append("}");

		return yaraRule.toString();
	}

	public String build() {
		return toString();
	}

	public void validate() {
		// XXX: validate via yara-java compiler
	}

	private void newBytesDigest() {
		try {
			bytesDigest = MessageDigest.getInstance("SHA-256");
			bytesDigestFinalized = false;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-256 algorithm not found", e);
		}
	}

	private void updateBytesDigest(byte[] bytes) {
		bytesDigest.update(bytes);
	}

	private byte[] finalBytesDigest() {
		bytesDigestFinalized = true;
		return bytesDigest.digest();
	}

	private String generateHashBasedRuleName() {

		byte[] hashBytes = finalBytesDigest();

		StringBuilder hexString = new StringBuilder();
		for (int i = 0; i < 16 && i < hashBytes.length; i++) {
			hexString.append(String.format("%02x", hashBytes[i]));
		}

		return String.format("GhidraYara_%s", hexString.toString());
	}

	public Date getCreationTimestamp() {
		return Utils.localDateTimeToDate(createdAt);
	}

	public Date getUpdatedTimestamp() {
		return Utils.localDateTimeToDate(updatedAt);
	}

	public String getIdentifier() {
		if (ruleName == null || (ruleName != null && ruleName.isBlank())) {
			ruleName = generateHashBasedRuleName();
		}

		return ruleName;
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return new Class<?>[] { String.class, // ruleName
			String.class, // author
			String.class, // description
			Long.class, // createdAt
			Long.class, // updatedAt
			String[].class, // tags
			String[].class, // bytes encoded

		};
	}

	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putString(ruleName);
		objStorage.putString(author);
		objStorage.putString(description);

		// timestamps could be stored as longs,
		objStorage.putLong(DateTimeUtils.toEpochNanos(createdAt));
		objStorage.putLong(DateTimeUtils.toEpochNanos(updatedAt));

		objStorage.putStrings((String[]) tags.toArray());

		saveMetaMap(objStorage);

		List<String> encodedBytes = byteArrays.stream().map(ByteArrayUtils::encode).collect(Collectors.toList());

		objStorage.putStrings((String[]) encodedBytes.toArray());
	}

	/**
	 * Notes about timestamps: Instead of strings we are using longs (nanosecond
	 * precision, 8 bytes each). There doesn't seem to be a point in storing human
	 * readable data in ObjectStorage anyway.
	 *
	 * Example: objStorage.putLong(DateTimeUtils.toEpochNanos(createdAt)); // save
	 * createdAt = DateTimeUtils.fromEpochNanos(objStorage.getLong()); // restore
	 *
	 * for ISO-8601 strings:
	 * objStorage.putString(DateTimeUtils.toIsoString(createdAt)); // save
	 * objStorage.putString(DateTimeUtils.toIsoString(updatedAt)); // save createdAt
	 * = DateTimeUtils.fromIsoString(objStorage.getString()); // restore createdAt =
	 * DateTimeUtils.fromIsoString(objStorage.getString()); // restore
	 */
	@Override
	public void restore(ObjectStorage objStorage) {
		ruleName = objStorage.getString();
		author = objStorage.getString();
		description = objStorage.getString();

		createdAt = DateTimeUtils.fromEpochNanos(objStorage.getLong());
		updatedAt = DateTimeUtils.fromEpochNanos(objStorage.getLong());

		tags = Arrays.asList(objStorage.getStrings());

		restoreMetaMap(objStorage);

		List<String> encodedBytes = Arrays.asList(objStorage.getStrings());

		// Convert Base64 strings back into byte[] arrays
		List<byte[]> bytesDecoded = encodedBytes.stream().map(ByteArrayUtils::decode).collect(Collectors.toList());

		for (byte[] bytes : bytesDecoded) {
			addByteArray(bytes);
		}
	}

	@Override
	public int getSchemaVersion() {
		return serialVersionUID;
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	// @see ghidra.util.Saveable#upgrade(ghidra.util.ObjectStorage, int,
	// ghidra.util.ObjectStorage)
	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean isPrivate() {
		return false;
	}

	// Serializes the Map<String, String> into two lists and stores them
	private void saveMetaMap(ObjectStorage objStorage) {
		List<String> keys = new ArrayList<>();
		List<String> values = new ArrayList<>();

		// Split the map into keys and values lists
		for (Map.Entry<String, String> entry : meta.entrySet()) {
			keys.add(entry.getKey());
			values.add(entry.getValue());
		}

		// Store the keys and values lists in order
		objStorage.putStrings((String[]) keys.toArray()); // Store keys
		objStorage.putStrings((String[]) values.toArray()); // Store values
	}

	// Restores the Map<String, String> from ObjectStorage
	private void restoreMetaMap(ObjectStorage objStorage) {
		String[] keys = objStorage.getStrings();
		String[] values = objStorage.getStrings();

		Map<String, String> map = new java.util.HashMap<>();
		for (int i = 0; i < keys.length; i++) {
			map.put(keys[i], values[i]);
		}

		meta = map;
	}
}
