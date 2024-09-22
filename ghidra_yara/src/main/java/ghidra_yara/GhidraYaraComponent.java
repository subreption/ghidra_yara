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

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class GhidraYaraComponent extends ComponentProvider {

	private JPanel panel;
	private DockingAction action;
	private GhidraYaraPlugin yaraPlugin;

	static final String MENU_GROUP_NAME = "GhidraYara";
	static final String PARENT_CONTEXT_MENU_NAME = "YARA";

	static final String GENERATE_RULE_CONTEXT_MENU_NAME = "Generate rule from selected data";
	static final String GENERATE_RULE_CONTEXT_MENU_DESC = "Generates a reusable YARA rule from selected data";
	static final String GENERATE_RULE_CONTEXT_MENU_HELP = "yara_generate_rule";

	public GhidraYaraComponent(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);

		yaraPlugin = (GhidraYaraPlugin) plugin;

		createActions();
	}

	private void createActions() {
		action = new DockingAction("ListingContext YARA Generator Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				ListingActionContext listingContext = (ListingActionContext) context;

				Program program = listingContext.getProgram();
				Memory memory = program.getMemory();
				ProgramSelection selection = listingContext.getSelection();

				if (selection == null || selection.isEmpty()) {
					Msg.error(this, "No bytes selected.");
					return;
				}

				Msg.debug(this, "Action triggered on address: " + listingContext.getAddress());

				for (AddressRange range : selection) {
					Address startAddress = range.getMinAddress();
					long length = range.getLength();

					byte[] bytes = new byte[(int) length];

					try {
						memory.getBytes(startAddress, bytes);
						yaraPlugin.generateYaraRule(program, range, bytes);
					} catch (MemoryAccessException e) {
						Msg.error(this, "Error reading selected bytes from memory.", e);
					}
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				// Enable this action only if the context is a ListingActionContext (ex.
				// right-clicked on code/data)
				return context instanceof ListingActionContext;
			}
		};

		action.setPopupMenuData(new MenuData(new String[] { PARENT_CONTEXT_MENU_NAME, GENERATE_RULE_CONTEXT_MENU_NAME },
				null, MENU_GROUP_NAME));

		action.setHelpLocation(new HelpLocation(getName(), GENERATE_RULE_CONTEXT_MENU_HELP));
		action.setEnabled(true);
		action.setDescription(GENERATE_RULE_CONTEXT_MENU_DESC);
		dockingTool.addAction(action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
