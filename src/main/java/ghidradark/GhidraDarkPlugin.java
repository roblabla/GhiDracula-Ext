/* ###
 * IP: GHIDRA
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
package ghidradark;

import java.awt.Color;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import javax.swing.*;

import docking.widgets.AbstractGCellRenderer;
import docking.widgets.filter.FilterTextField;
import docking.widgets.table.GTableHeaderRenderer;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.dynamic.loading.ClassReloadingStrategy;
import net.bytebuddy.agent.ByteBuddyAgent;

import com.bulenkov.darcula.DarculaLaf;
import javax.swing.plaf.basic.BasicLookAndFeel;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(status = PluginStatus.STABLE, packageName = "Ghidra Dark", category = PluginCategoryNames.EXAMPLES, shortDescription = "Plugin short description goes here.", description = "Plugin long description goes here.")
//@formatter:on
public class GhidraDarkPlugin extends ProgramPlugin {

	static String NAME = "Ghidra Dark";

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraDarkPlugin(PluginTool tool) {
		super(tool, true, true);

	}

	static void setFinalStatic(Class<?> cls, String fieldName, Object newValue) {
		try {
			Field field = cls.getDeclaredField(fieldName);
			field.setAccessible(true);

			Field modifiersField = Field.class.getDeclaredField("modifiers");
			modifiersField.setAccessible(true);
			modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

			field.set(null, newValue);

		} catch (NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
			e.printStackTrace();
		}
	}

	static {

		BasicLookAndFeel dracula = new DarculaLaf();
		ByteBuddyAgent.install();

		try {
			UIManager.setLookAndFeel(dracula);
		} catch (Exception e) {
			e.printStackTrace();
		}
		setFinalStatic(FilterTextField.class, "FILTERED_BACKGROUND_COLOR", new Color(0x11, 0x11, 0x11));
		setFinalStatic(AbstractGCellRenderer.class, "ALTERNATE_BACKGROUND_COLOR", new Color(0x32, 0x32, 0x32));
		setFinalStatic(GTableHeaderRenderer.class, "PRIMARY_SORT_GRADIENT_START", new Color(0x5B, 0x67, 0x74));
		setFinalStatic(GTableHeaderRenderer.class, "PRIMARY_SORT_GRADIENT_END", new Color(0x52, 0x52, 0x52));
		setFinalStatic(GTableHeaderRenderer.class, "DEFAULT_GRADIENT_START", new Color(0x3B, 0x47, 0x54));
		setFinalStatic(GTableHeaderRenderer.class, "DEFAULT_GRADIENT_END", new Color(0x32, 0x32, 0x32));

		try {
			Method m = AbstractGCellRenderer.class.getDeclaredMethod("getDefaultBackgroundColor");
			new ByteBuddy()
					.redefine(AbstractGCellRenderer.class)
					.method(ElementMatchers.is(m))
					.intercept(MethodCall.invoke(GhidraDarkPlugin.class.getMethod("getDefaultBackgroundColor")))
					.make()
					.load(AbstractGCellRenderer.class.getClassLoader(), ClassReloadingStrategy.fromInstalledAgent());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static Color getDefaultBackgroundColor() {
		return new Color(0x2b, 0x2b, 0x2b);
	}

	@Override
	public void init() {
		super.init();

	}

}
