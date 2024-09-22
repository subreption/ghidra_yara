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

/**
 *
 */
package ghidra_yara;

import java.awt.BorderLayout;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GTable;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.ResourceManager;

/**
 *
 */
public class YaraRuleTableProvider extends ComponentProviderAdapter {
	private JPanel mainPanel;
	private GTable table;
	// private YaraRuleTableContextMenuAction action;
	private DockingAction action;
	private GhidraYaraRuleTableModel tableModel;

	static final String MENU_GROUP_NAME = "GhidraYaraTable";
	static final String PARENT_CONTEXT_MENU_NAME = "YARA";

	// Submenus
	static final String EXPORT_MENU_NAME = "Save Rule(s)";
	static final String REMOVE_MENU_NAME = "Remove rule(s)";
	static final String VERIFY_MENU_NAME = "Verify rule(s)";

	// Submenu items
	static final String EXPORT_SELECTED_CONTEXT_MENU_DESC = "Exports selected YARA rules to file(s)";
	static final String EXPORT_SELECTED_CONTEXT_MENU_HELP = "yara_gen_export_selected";

	static final String EXPORT_ALL_SELECTED_CONTEXT_MENU_DESC = "Exports all YARA rules to file(s)";
	static final String EXPORT_ALL_SELECTED_CONTEXT_MENU_HELP = "yara_gen_export_all";

	static final String VERIFY_SELECTED_CONTEXT_MENU_DESC = "Runs an instance of the YARA scanner with the selected rules";
	static final String VERIFY_SELECTED_CONTEXT_MENU_HELP = "yara_gen_verify_selected";

	static final String REMOVE_ALL_CONTEXT_MENU_DESC = "Remove all generated rules";
	static final String REMOVE_ALL_CONTEXT_MENU_HELP = "yara_gen_remove_all";

	static final String EXPORT_SELECTED_CONTEXT_MENU_NAME = "Selected";
	static final String EXPORT_ALL_CONTEXT_MENU_NAME = "All";

	static final String REMOVE_SELECTED_CONTEXT_MENU_NAME = "Selected";
	static final String REMOVE_ALL_CONTEXT_MENU_NAME = "All";

	static final String VERIFY_SELECTED_CONTEXT_MENU_NAME = "Selected";
	static final String VERIFY_ALL_CONTEXT_MENU_NAME = "All";

	public YaraRuleTableProvider(PluginTool tool, String owner) {
		super(tool, "Generated YARA Rules", owner);

		// Set up the table model and GTable
		tableModel = new GhidraYaraRuleTableModel(new ArrayList<>()); // Initially empty
		table = new GTable(tableModel);

		// XXX: Until this is documented properly (GIcon not loading our resource theme
		// file)
		// see ./Ghidra/Framework/Gui/src/main/java/generic/theme/GIcon.java
		// setIcon(new GIcon("icon.yara"));
		setIcon(ResourceManager.loadImage("images/yara_icon.png"));

		// Set up the panel layout
		mainPanel = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(table);
		mainPanel.add(scrollPane, BorderLayout.CENTER);

		createActions();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	// Method to update the table with new rules
	public void updateRules(List<GhidraYaraRule> rules) {
		tableModel.setRules(rules);
	}

	private void createActions() {
		action = new DockingAction("YaraRuleTable Context Export Selected Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				exportSelected(context);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context.getComponentProvider() instanceof YaraRuleTableProvider) {
					if (table.getSelectedRowCount() > 0) {
						return true;
					}
				}

				return false;
			}
		};

		action.setPopupMenuData(new MenuData(new String[] { EXPORT_MENU_NAME, EXPORT_SELECTED_CONTEXT_MENU_NAME }, null,
				MENU_GROUP_NAME));

		action.setHelpLocation(new HelpLocation(getName(), EXPORT_SELECTED_CONTEXT_MENU_HELP));
		action.setEnabled(true);
		action.setDescription(EXPORT_SELECTED_CONTEXT_MENU_DESC);
		tool.addAction(action);

		action = new DockingAction("YaraRuleTable Context Export All Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				exportAll(context);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context.getComponentProvider() instanceof YaraRuleTableProvider) {
					if (table.getRowCount() > 0) {
						return true;
					}
				}

				return false;
			}
		};

		action.setPopupMenuData(
				new MenuData(new String[] { EXPORT_MENU_NAME, EXPORT_ALL_CONTEXT_MENU_NAME }, null, MENU_GROUP_NAME));

		action.setHelpLocation(new HelpLocation(getName(), EXPORT_ALL_SELECTED_CONTEXT_MENU_HELP));
		action.setEnabled(true);
		action.setDescription(EXPORT_ALL_SELECTED_CONTEXT_MENU_DESC);
		tool.addAction(action);

		action = new DockingAction("YaraRuleTable Context Verify Selected Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				verifySelected(context);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context.getComponentProvider() instanceof YaraRuleTableProvider) {
					if (table.getSelectedRowCount() > 0) {
						return true;
					}
				}

				return false;
			}
		};

		action.setPopupMenuData(new MenuData(new String[] { VERIFY_MENU_NAME, VERIFY_SELECTED_CONTEXT_MENU_NAME }, null,
				MENU_GROUP_NAME));

		action.setHelpLocation(new HelpLocation(getName(), VERIFY_SELECTED_CONTEXT_MENU_HELP));
		action.setEnabled(true);
		action.setDescription(VERIFY_SELECTED_CONTEXT_MENU_DESC);
		tool.addAction(action);

		action = new DockingAction("YaraRuleTable Context Remove All Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clear(context);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context.getComponentProvider() instanceof YaraRuleTableProvider) {
					if (table.getRowCount() > 0) {
						return true;
					}
				}

				return false;
			}
		};

		action.setPopupMenuData(
				new MenuData(new String[] { REMOVE_MENU_NAME, REMOVE_ALL_CONTEXT_MENU_NAME }, null, MENU_GROUP_NAME));

		action.setHelpLocation(new HelpLocation(getName(), REMOVE_ALL_CONTEXT_MENU_HELP));
		action.setEnabled(true);
		action.setDescription(REMOVE_ALL_CONTEXT_MENU_DESC);
		tool.addAction(action);
	}

	private List<GhidraYaraRule> collectImmutableRules(int[] rows) {
		List<GhidraYaraRule> tableList = tableModel.getImmutableList();
		List<GhidraYaraRule> rules;

		if (rows == null) {
			rules = tableList;
		} else {
			rules = new ArrayList<>();

			for (int row : rows) {
				rules.add(tableList.get(row));
			}
		}

		return Collections.unmodifiableList(rules);
	}

	private void clear(ActionContext context) {
		tableModel.clearRules();
	}

	private void exportAll(ActionContext context) {
		List<GhidraYaraRule> rules = collectImmutableRules(null);

		showFileDialogAndExport(context, rules, EXPORT_ALL_CONTEXT_MENU_NAME);
	}

	private void exportSelected(ActionContext context) {
		int[] selectedRows = table.getSelectedRows();
		List<GhidraYaraRule> rules = collectImmutableRules(selectedRows);

		showFileDialogAndExport(context, rules, EXPORT_SELECTED_CONTEXT_MENU_NAME);
	}

	private void verifySelected(ActionContext context) {
		List<GhidraYaraRule> list = collectImmutableRules(null);
		Msg.info(this, list.toString());
	}

	private void showFileDialogAndExport(ActionContext context, List<GhidraYaraRule> rules, String dialogTitle) {
		// 'null' can be replaced with a valid window or component for modal behavior
		GhidraFileChooser fileChooser = new GhidraFileChooser(null);

		fileChooser.setTitle(dialogTitle);
		fileChooser.setApproveButtonText("Save");
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);

		File file = fileChooser.getSelectedFile();

		if (file != null) {
			try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
				// TODO: should be user selectable
//				Program program = (...);
//
//				writer.write("// Exported from Ghidra");
//				writer.newLine();
//
//				if (program != null) {
//					writer.write("// Program Name: " + program.getDomainFile().getName());
//					writer.newLine();
//					writer.write("// Language: "
//							+ program.getLanguage().getLanguageDescription().getLanguageID().getIdAsString());
//					writer.newLine();
//					writer.write("// Image Base: " + program.getImageBase().toString());
//					writer.newLine();
//				}
//
//				writer.newLine();

				for (GhidraYaraRule rule : rules) {
					writer.write(rule.toString());
					writer.newLine();
					writer.newLine();
				}

				Msg.info(this, "Successfully exported Yara rules to: " + file.getAbsolutePath());
			} catch (IOException e) {
				Msg.showError(this, null, "Export Failed", "Failed to export Yara rules", e);
			}
		} else {
			Msg.info(this, "Export canceled by user.");
		}
	}
}
