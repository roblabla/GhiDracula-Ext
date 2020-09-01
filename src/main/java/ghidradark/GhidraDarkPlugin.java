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

import java.awt.*;
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

	static void setStatic(Class<?> cls, String fieldName, Object newValue) {
		try {
			Field field = cls.getDeclaredField(fieldName);
			field.setAccessible(true);
			field.set(null, newValue);

		} catch (NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
			e.printStackTrace();
		}
	}

	static void hookMethod(Class<?> cls, String methodName, String hookName, Class<?>[] paramTypes, FieldInfo... fields) {
		try {
			// Get the method to hook
			Method toHook = cls.getDeclaredMethod(methodName, paramTypes);

			// Calculate the argument size of the hook we're installing.
			int hookParamLength = paramTypes.length + fields.length;
			if (!Modifier.isStatic(toHook.getModifiers())) {
				hookParamLength += 1;
			}

			// Create the argument class list for the hook we're installing.
			Class<?>[] hookParams = new Class[hookParamLength];
			int i = 0;
			if (!Modifier.isStatic(toHook.getModifiers())) {
				hookParams[i] = cls;
				i += 1;
			}
			for (int j = 0; j < paramTypes.length; i += 1, j += 1) {
				hookParams[i] = paramTypes[j];
			}
			for (int j = 0; j < fields.length; i += 1, j += 1) {
				hookParams[i] = fields[j].ty;
			}

			// Find the hook method.
			Method hook = GhidraDarkPlugin.class.getDeclaredMethod(hookName, hookParams);

			// Generate the MethodCall implementation
			MethodCall methodCall = MethodCall.invoke(hook);
			if (!Modifier.isStatic(toHook.getModifiers())) {
				methodCall = methodCall.withThis();
			}
			methodCall = methodCall.withAllArguments();
			for (FieldInfo f : fields) {
				methodCall = methodCall.withField(f.name);
			}

			// Install our hook
			new ByteBuddy()
				.redefine(cls)
				.method(ElementMatchers.is(toHook))
				.intercept(methodCall)
				.make()
				.load(cls.getClassLoader(), ClassReloadingStrategy.fromInstalledAgent());
		} catch (NoSuchMethodException | SecurityException e) {
			e.printStackTrace();
		}
	}
	static Class<?>[] c(Class<?>... classes) {
		return classes;
	}

	static FieldInfo f(Class<?> ty, String name) {
		return new FieldInfo(ty, name);
	}


	static Color AbstractGCellRenderer_DEFAULT_BACKGROUND_COLOR = new Color(0x2b, 0x2b, 0x2b);
	static Color AbstractGCellRenderer_ALTERNATE_BACKGROUND_COLOR = new Color(0x32, 0x32, 0x32);
	static Color FilterTextField_FILTERED_BACKGROUND_COLOR = new Color(0x11, 0x11, 0x11);
	static Color GTableHeaderRenderer_PRIMARY_SORT_GRADIENT_START = new Color(0x5B, 0x67, 0x74);
	static Color GTableHeaderRenderer_PRIMARY_SORT_GRADIENT_END = new Color(0x52, 0x52, 0x52);
	static Color GTableHeaderRenderer_DEFAULT_GRADIENT_START = new Color(0x3B, 0x47, 0x54);
	static Color GTableHeaderRenderer_DEFAULT_GRADIENT_END = new Color(0x32, 0x32, 0x32);

	public static Color getDefaultBackgroundColor(AbstractGCellRenderer self) {
		return AbstractGCellRenderer_DEFAULT_BACKGROUND_COLOR;
	}

	public static Color getBackgroundColorForRow(AbstractGCellRenderer self, int row) {
		if ((row & 1) == 1) {
			return getDefaultBackgroundColor(self);
		}
		return AbstractGCellRenderer_ALTERNATE_BACKGROUND_COLOR;
	}

	public static Paint getBackgroundPaint(GTableHeaderRenderer self, boolean isPaintingPrimarySortColumn) {
		if (isPaintingPrimarySortColumn) {
			return new GradientPaint(0, 0, GTableHeaderRenderer_PRIMARY_SORT_GRADIENT_START, 0, self.getHeight() - 11,
				GTableHeaderRenderer_PRIMARY_SORT_GRADIENT_END, true);
		}
		return new GradientPaint(0, 0, GTableHeaderRenderer_DEFAULT_GRADIENT_START, 0, self.getHeight() - 11,
			GTableHeaderRenderer_DEFAULT_GRADIENT_END, true);
	}

	static void install() {
		ByteBuddyAgent.install();

		setStatic(FilterTextField.class, "FILTERED_BACKGROUND_COLOR", FilterTextField_FILTERED_BACKGROUND_COLOR);
		hookMethod(AbstractGCellRenderer.class, "getBackgroundColorForRow", "getBackgroundColorForRow", c(int.class));
		// It looks like hooking the same class twice causes the earlier hook to be lost... oops.
		//hookMethod(AbstractGCellRenderer.class, "getDefaultBackgroundColor", "getDefaultBackgroundColor", c());
		hookMethod(GTableHeaderRenderer.class, "getBackgroundPaint", "getBackgroundPaint", c(), f(boolean.class, "isPaintingPrimarySortColumn"));

		try {
			BasicLookAndFeel dracula = new DarculaLaf();
			UIManager.setLookAndFeel(dracula);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	static {
		install();
	}

	@Override
	public void init() {
		super.init();

	}

}
