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

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import javax.swing.JOptionPane;
import javax.swing.table.AbstractTableModel;

public class GhidraYaraRuleTableModel extends AbstractTableModel
{
	private static final String COLUMN_NAME_IDENTIFIER = "Identifier";
	private static final String COLUMN_NAME_AUTHOR = "Author";
	private static final String COLUMN_NAME_DESCRIPTION = "Description";
	private static final String COLUMN_NAME_TAGS = "Tags";
	private static final String COLUMN_NAME_CREATED = "Created";
	private static final String COLUMN_NAME_UPDATED = "Updated";

	private static final String[] COLUMN_NAMES = {
			COLUMN_NAME_IDENTIFIER,
			COLUMN_NAME_AUTHOR,
			COLUMN_NAME_DESCRIPTION,
			COLUMN_NAME_TAGS,
			COLUMN_NAME_CREATED,
			COLUMN_NAME_UPDATED
	};

	private static final List<String> EDITABLE_COLUMNS = Arrays.asList(
			COLUMN_NAME_IDENTIFIER,
			COLUMN_NAME_AUTHOR,
			COLUMN_NAME_DESCRIPTION
			);

	private static final Map<String, BiConsumer<GhidraYaraRule, String>> columnSetters = new HashMap<>();

	static {
		columnSetters.put(COLUMN_NAME_AUTHOR, GhidraYaraRule::setAuthor);
		columnSetters.put(COLUMN_NAME_IDENTIFIER, GhidraYaraRule::setIdentifier);
		columnSetters.put(COLUMN_NAME_DESCRIPTION, GhidraYaraRule::setDescription);
	}



	private List<GhidraYaraRule> rules;
	private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	public GhidraYaraRuleTableModel(List<GhidraYaraRule> rules) {
		this.rules = rules;
	}

	@Override
	public int getRowCount() {
		return rules.size();
	}

	@Override
	public int getColumnCount() {
		return COLUMN_NAMES.length;
	}

	@Override
	public String getColumnName(int column) {
		return COLUMN_NAMES[column];
	}

	private int getColumnIndex(String columnName) {
		return  Arrays.asList(COLUMN_NAMES).indexOf(columnName);
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex)
	{
		GhidraYaraRule rule = rules.get(rowIndex);
		String columnName = COLUMN_NAMES[columnIndex];

		if (COLUMN_NAME_IDENTIFIER.equals(columnName))
		{
			String newIdentifier = aValue.toString();

			// Check for uniqueness of the new identifier
			boolean isDuplicate = rules.stream()
					.filter(r -> !r.equals(rule))  // Exclude the current rule being edited
					.anyMatch(r -> r.getIdentifier().equals(newIdentifier));

			if (isDuplicate) {
				// TODO: to be replaced with our own cell renderer
				JOptionPane.showMessageDialog(null, "Identifier must be unique!",
						"Validation Error", JOptionPane.ERROR_MESSAGE);
				return;
			}
		}

		BiConsumer<GhidraYaraRule, String> setter = columnSetters.get(columnName);
		if (setter != null) {
			setter.accept(rule, aValue.toString());
			fireTableCellUpdated(rowIndex, columnIndex);
			fireTableCellUpdated(rowIndex, getColumnIndex(COLUMN_NAME_UPDATED));
		}
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex)
	{
		String columnName = COLUMN_NAMES[columnIndex];

		if (EDITABLE_COLUMNS.contains(columnName)) {
			return true;
		}

		return false;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		GhidraYaraRule rule = rules.get(rowIndex);
		switch (columnIndex) {
		case 0: return rule.getIdentifier();
		case 1: return rule.getAuthor();
		case 2: return rule.getDescription();
		case 3: return rule.getTags();
		case 4: return dateFormat.format(rule.getCreationTimestamp());
		case 5: return dateFormat.format(rule.getUpdatedTimestamp());
		default: return null;
		}
	}

	public void clearRules()
	{
		this.rules.clear();
		fireTableDataChanged();
	}

	public void setRules(List<GhidraYaraRule> rules) {
		this.rules = rules;
		fireTableDataChanged(); // Notify the table that the data has changed
	}

	public List<GhidraYaraRule> getImmutableList()
	{
		return Collections.unmodifiableList(rules);
	}
}
