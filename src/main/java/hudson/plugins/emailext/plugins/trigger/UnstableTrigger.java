package hudson.plugins.emailext.plugins.trigger;

import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.Build;
import hudson.model.Project;
import hudson.model.Result;
import hudson.plugins.emailext.plugins.EmailTrigger;
import hudson.plugins.emailext.plugins.EmailTriggerDescriptor;

public class UnstableTrigger extends EmailTrigger {
	public static final String TRIGGER_NAME = "Unstable";

	
	@Override
	public <P extends AbstractProject<P, B>, B extends AbstractBuild<P, B>> boolean trigger(
			B build) {
		Result buildResult = build.getResult();
		
		if(buildResult == Result.UNSTABLE)
			return true;
		
		return false;
	}
	
	@Override
	public EmailTriggerDescriptor getDescriptor() {
		return DESCRIPTOR;
	}
	
	public static DescriptorImpl DESCRIPTOR = new DescriptorImpl();
	
	public static final class DescriptorImpl extends EmailTriggerDescriptor{
		
		
		@Override
		public String getTriggerName() {
			return TRIGGER_NAME;
		}

		@Override
		public EmailTrigger newInstance() {
			return new UnstableTrigger();
		}
		
		@Override
		public String getHelpText() {
			return "An email will be sent any time the build is unstable.  If the \"Still Unstable\" "+
			       "trigger is configured, then a unstable email will not be sent if multiple builds" +
			       "are unstable without a successful build.";
		}
		
	}
	
	@Override
	public boolean getDefaultSendToDevs() {
		return true;
	}

	@Override
	public boolean getDefaultSendToList() {
		return true;
	}

}
