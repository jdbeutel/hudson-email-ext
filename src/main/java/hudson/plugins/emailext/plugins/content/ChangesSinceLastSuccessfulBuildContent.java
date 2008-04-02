package hudson.plugins.emailext.plugins.content;

import hudson.model.Build;
import hudson.model.Project;
import hudson.plugins.emailext.EmailType;
import hudson.plugins.emailext.plugins.EmailContent;

public class ChangesSinceLastSuccessfulBuildContent implements EmailContent {
	
	private static final String TOKEN = "CHANGES_SINCE_LAST_SUCCESS";

	public <P extends Project<P, B>, B extends Build<P, B>> String getContent(
			Build<P, B> build,
			EmailType emailType) {
		
		//Use this object since it already formats the changes per build
		ChangesSinceLastBuildContent changes = new ChangesSinceLastBuildContent();
		
		Build<P,B> lastSuccessfulBuild = build.getPreviousNotFailedBuild();
		
		StringBuffer sb = new StringBuffer();
		
		while(lastSuccessfulBuild!=build){
			sb.append("Changes for Build #");
			sb.append(lastSuccessfulBuild.getNumber());
			sb.append("\n");
			sb.append(changes.getContent(build, emailType));
			sb.append("\n");
			lastSuccessfulBuild = lastSuccessfulBuild.getNextBuild();
		}
		
        return sb.toString();
	}

	public String getToken() {
		return TOKEN;
	}

	public boolean hasNestedContent() {
		return false;
	}

	public String getHelpText() {
		return "Displays the changes since the last successful build. (Not implemented yet.)";
	}

}
