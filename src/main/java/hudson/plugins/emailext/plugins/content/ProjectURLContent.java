package hudson.plugins.emailext.plugins.content;

import hudson.Util;
import hudson.model.Build;
import hudson.model.Project;
import hudson.plugins.emailext.EmailType;
import hudson.plugins.emailext.plugins.EmailContent;

public class ProjectURLContent implements EmailContent {
	
	private static final String TOKEN = "PROJECT_URL";

	public <P extends Project<P, B>, B extends Build<P, B>> String getContent(
			Build<P, B> build,
			EmailType emailType) {
		return "$HUDSON_URL/" + Util.encode(build.getProject().getUrl());
	}

	public String getToken() {
		return TOKEN;
	}

	public boolean hasNestedContent() {
		return true;
	}

	public String getHelpText() {
		return "Displays a URL to the project's page.";
		
	}

}
