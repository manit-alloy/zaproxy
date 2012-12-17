/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.api;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.network.ConnectionParam;
import org.zaproxy.zap.extension.anticsrf.AntiCsrfAPI;
import org.zaproxy.zap.extension.ascan.ActiveScanAPI;
import org.zaproxy.zap.extension.auth.AuthAPI;
import org.zaproxy.zap.extension.autoupdate.AutoUpdateAPI;
import org.zaproxy.zap.extension.autoupdate.OptionsParamCheckForUpdates;
import org.zaproxy.zap.extension.params.ParamsAPI;
import org.zaproxy.zap.extension.search.SearchAPI;
import org.zaproxy.zap.extension.spider.SpiderAPI;
import org.zaproxy.zap.spider.SpiderParam;

public class PythonAPIGenerator {
	private List<ApiImplementor> implementors = new ArrayList<ApiImplementor> ();
	private File dir = new File("python/api/src/zapv2"); 
	
	private final String HEADER = 
			"# Zed Attack Proxy (ZAP) and its related class files.\n" +
			"#\n" +
			"# ZAP is an HTTP/HTTPS proxy for assessing web application security.\n" +
			"#\n" +
			"# Copyright 2012 ZAP development team\n" +
			"#\n" +
			"# Licensed under the Apache License, Version 2.0 (the \"License\");\n" +
			"# you may not use this file except in compliance with the License.\n" +
			"# You may obtain a copy of the License at\n" +
			"#\n" +
			"#   http://www.apache.org/licenses/LICENSE-2.0\n" +
			"#\n" +
			"# Unless required by applicable law or agreed to in writing, software\n" +
			"# distributed under the License is distributed on an \"AS IS\" BASIS,\n" +
			"# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n" +
			"# See the License for the specific language governing permissions and\n" +
			"# limitations under the License.\n" +
			"\"\"\"\n" +
			"This file was automatically generated.\n" +
			"\"\"\"\n\n";

	private ResourceBundle msgs = ResourceBundle.getBundle("lang." + Constant.MESSAGES_PREFIX, Locale.ENGLISH);

	public void addImplementor(ApiImplementor imp) {
		this.implementors.add(imp);
	}
	

	public void generatePythonFiles() throws IOException {
		for (ApiImplementor imp : this.implementors) {
			this.generatePythonComponent(imp);
		}
	}
	
	private void generatePythonElement(ApiElement element, String component, String type, Writer out) throws IOException {
		this.generatePythonElement(element, component, type, out, false);
		
	}
	private void generatePythonElement(ApiElement element, String component, 
			String type, Writer out, boolean incComponentCol) throws IOException {
		boolean hasParams = false;
		out.write("\tdef " + element.getName() + "(self");

		if (element.getMandatoryParamNames() != null) {
			for (String param : element.getMandatoryParamNames()) {
				out.write(", " + param.toLowerCase());
				hasParams = true;
			}
		}
		if (element.getOptionalParamNames() != null) {
			for (String param : element.getOptionalParamNames()) {
				out.write(", " + param.toLowerCase() + "=''");
				hasParams = true;
			}
		}
		out.write("):\n");

		// Add description if defined
		String descTag = element.getDescriptionTag();
		if (descTag == null) {
			// This is the default, but it can be overriden by the getDescriptionTag method if required
			descTag = component + ".api." + type + "." + element.getName();
		}
		try {
			String desc = msgs.getString(descTag);
			out.write("\t\t\"\"\"\n");
			out.write("\t\t" + desc + "\n");
			out.write("\t\t\"\"\"\n");
		} catch (Exception e) {
			// Might not be set, so just print out the ones that are missing
			System.out.println("No i18n for: " + descTag);
		}

		out.write("\t\treturn self.zap._request(self.zap.base + '" + 
				component + "/" + type + "/" + element.getName() + "/'");
		
		// , {'url': url}))
		if (hasParams) {
			out.write(", {");
			boolean first = true;
			if (element.getMandatoryParamNames() != null) {
				for (String param : element.getMandatoryParamNames()) {
					if (first) {
						first = false;
					} else {
						out.write(", ");
					}
					out.write("'" + param + "' : " + param.toLowerCase());
				}
			}
			if (element.getOptionalParamNames() != null) {
				for (String param : element.getOptionalParamNames()) {
					if (first) {
						first = false;
					} else {
						out.write(", ");
					}
					out.write("'" + param + "' : " + param.toLowerCase());
				}
			}
			out.write("}");
		}
		out.write(")\n\n");
		
	}

	private void generatePythonComponent(ApiImplementor imp) throws IOException {
		File f = new File(this.dir, imp.getPrefix() + ".py");
		System.out.println("Generating " + f.getAbsolutePath());
		FileWriter out = new FileWriter(f);
		out.write(HEADER);
		out.write("class " + imp.getPrefix() + "(object):\n\n");
		out.write("\tdef __init__(self, zap):\n");
		out.write("\t\tself.zap = zap\n");
		out.write("\n");
		
		for (ApiElement view : imp.getApiViews()) {
			this.generatePythonElement(view, imp.getPrefix(), "view", out);
		}
		for (ApiElement action : imp.getApiActions()) {
			this.generatePythonElement(action, imp.getPrefix(), "action", out);
		}
		for (ApiElement other : imp.getApiOthers()) {
			this.generatePythonElement(other, imp.getPrefix(), "other", out);
		}
		out.write("\n");
		out.close();
	}

	public static void main(String[] args) throws Exception {
		// Command for generating a python version of the ZAP API
		
		PythonAPIGenerator wapi = new PythonAPIGenerator();
		ApiImplementor api;

		wapi.addImplementor(new AntiCsrfAPI(null));
		wapi.addImplementor(new SearchAPI(null));

		api = new AutoUpdateAPI(null);
		api.addApiOptions(new OptionsParamCheckForUpdates());
		wapi.addImplementor(api);

		api = new SpiderAPI(null);
		api.addApiOptions(new SpiderParam());
		wapi.addImplementor(api);

		api = new CoreAPI();
        api.addApiOptions(new ConnectionParam());
		wapi.addImplementor(api);
		
		wapi.addImplementor(new ParamsAPI(null));
		
		api = new ActiveScanAPI(null);
		api.addApiOptions(new ScannerParam());
		wapi.addImplementor(api);
		
		wapi.addImplementor(new AuthAPI(null));
		
		wapi.generatePythonFiles();
		
	}

}