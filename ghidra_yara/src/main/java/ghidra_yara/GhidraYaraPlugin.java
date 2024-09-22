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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
		status = PluginStatus.RELEASED,
		packageName = CorePluginPackage.NAME,
		category = PluginCategoryNames.ANALYSIS,
		shortDescription = "FIXME",
		description = "FIXME",
		servicesRequired = {ConsoleService.class, CodeViewerService.class}
		)

//@formatter:on
public class GhidraYaraPlugin extends ProgramPlugin {
	public final static String PLUGIN_NAME = "GhidraYaraPlugin";

	private GhidraYaraComponent uiComponent;
	private YaraRuleTableProvider yaraRuleTableProvider;

	private List<GhidraYaraRule> ruleList;

	private ConsoleService consoleService;
	private CodeViewerService codeViewerService;

	private static final String YARA_RULES_PROPERTY = "GhidraYaraRules";
	private static final String OPTIONS_CATEGORY = "YARA";
	private static final String OPTION_DEFAULT_AUTHOR = "Default YARA Rule Author";

	private String defaultAuthor;

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraYaraPlugin(PluginTool tool) {
		super(tool);

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		uiComponent = new GhidraYaraComponent(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";

		uiComponent.setHelpLocation(new HelpLocation(topicName, anchorName));

		// Create and register the YARA rule provider panel
		yaraRuleTableProvider = new YaraRuleTableProvider(tool, getName());

		tool.addComponentProvider(yaraRuleTableProvider, false);

		ruleList = new ArrayList<>();

		// Register options for the plugin
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		options.registerOption(OPTION_DEFAULT_AUTHOR, pluginName, new HelpLocation("YARA", "DefaultAuthor"),
				"Default author name for generated YARA rules.");

		defaultAuthor = options.getString(OPTION_DEFAULT_AUTHOR, pluginName);

		options.addOptionsChangeListener(new GhidraYaraPluginOptionsListener());

		Msg.info(this, "Initialized Yara plugin...");
	}

	@Override
	public void init() {
		super.init();

		consoleService = tool.getService(ConsoleService.class);
		codeViewerService = tool.getService(CodeViewerService.class);
	}

	public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
		if (OPTION_DEFAULT_AUTHOR.equals(optionName)) {
			defaultAuthor = (String) newValue;
		}
	}

	private GhidraYaraRule toYaraRule(byte[] bytes) {
		GhidraYaraRule yaraRule = new GhidraYaraRule(bytes);

		return yaraRule;
	}

	private void addGeneratedYaraRule(GhidraYaraRule yaraRule) {
		ruleList.add(yaraRule);

		yaraRuleTableProvider.updateRules(ruleList);

		// Show the panel if it is hidden
		tool.showComponentProvider(yaraRuleTableProvider, true);

		return;
	}

	public void generateYaraRule(Program program, AddressRange range, byte[] bytes) {
		String msg;
		GhidraYaraRule yaraRule;

		yaraRule = toYaraRule(bytes);
		yaraRule.setAuthor(defaultAuthor);
		yaraRule.setDescription(String.format("Automatically generated for %s", range.toString()));

		msg = String.format("Generated Yara Rule `%s` for %d bytes from %s", yaraRule.getIdentifier(), bytes.length,
				range.toString());

		consoleService.addMessage(getName(), msg);
		Msg.info(this, msg);

		addGeneratedYaraRule(yaraRule);
	}

	private class GhidraYaraPluginOptionsListener implements OptionsChangeListener {

		@Override
		public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
			this.optionsChanged(options, name, oldValue, newValue);
		}
	}

}
