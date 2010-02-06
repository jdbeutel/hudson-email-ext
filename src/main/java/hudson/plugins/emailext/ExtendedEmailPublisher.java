package hudson.plugins.emailext;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.*;
import hudson.plugins.emailext.plugins.ContentBuilder;
import hudson.plugins.emailext.plugins.EmailTrigger;
import hudson.plugins.emailext.plugins.EmailTriggerDescriptor;
import hudson.scm.ChangeLogSet.Entry;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.MailMessageIdAction;
import hudson.tasks.Mailer;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.*;

import javax.mail.Address;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.nio.charset.Charset;

import javax.mail.Address;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.ServletException;

import net.sf.json.JSONObject;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * {@link Publisher} that sends notification e-mail.
 *
 * @author kyle.sweeney@valtech.com
 *
 */
public class ExtendedEmailPublisher extends Notifier {
	
	private static final Logger LOGGER = Logger.getLogger(Mailer.class.getName());

	public static final String COMMA_SEPARATED_SPLIT_REGEXP = "[,\\s]+";

	private static final Map<String,EmailTriggerDescriptor> EMAIL_TRIGGER_TYPE_MAP = new HashMap<String,EmailTriggerDescriptor>();
	
	public static final String DEFAULT_SUBJECT_TEXT = "$PROJECT_NAME - Build # $BUILD_NUMBER - $BUILD_STATUS!";
	public static final String DEFAULT_BODY_TEXT = "$PROJECT_NAME - Build # $BUILD_NUMBER - $BUILD_STATUS:\n\n" +
		"Check console output at $BUILD_URL to view the results.";
	
	public static final String PROJECT_DEFAULT_SUBJECT_TEXT = "$PROJECT_DEFAULT_SUBJECT";
	public static final String PROJECT_DEFAULT_BODY_TEXT = "$PROJECT_DEFAULT_CONTENT";

    public static final String CHARSET = "utf-8";
    
    private static final String DEFAULT_CHARSET_SENTINAL = "default";

    public static void addEmailTriggerType(EmailTriggerDescriptor triggerType) throws EmailExtException {
		if(EMAIL_TRIGGER_TYPE_MAP.containsKey(triggerType.getMailerId()))
			throw new EmailExtException("An email trigger type with name " +
					triggerType.getTriggerName() + " was already added.");
		EMAIL_TRIGGER_TYPE_MAP.put(triggerType.getMailerId(), triggerType);
	}
	
	public static void removeEmailTriggerType(EmailTriggerDescriptor triggerType) {
		if(EMAIL_TRIGGER_TYPE_MAP.containsKey(triggerType.getMailerId()))
			EMAIL_TRIGGER_TYPE_MAP.remove(triggerType.getMailerId());
	}
	
	public static EmailTriggerDescriptor getEmailTriggerType(String mailerId) {
		return EMAIL_TRIGGER_TYPE_MAP.get(mailerId);
	}
	
	public static Collection<EmailTriggerDescriptor> getEmailTriggers() {
		return EMAIL_TRIGGER_TYPE_MAP.values();
	}
	
	public static Collection<String> getEmailTriggerNames() {
		return EMAIL_TRIGGER_TYPE_MAP.keySet();
	}
	
	public static List<EmailTrigger> getTriggersForNonConfiguredInstance() {
		List<EmailTrigger> retList = new ArrayList<EmailTrigger>();
		for(String mailerId : EMAIL_TRIGGER_TYPE_MAP.keySet()) {
			retList.add(EMAIL_TRIGGER_TYPE_MAP.get(mailerId).getNewInstance(null));
		}
		return retList;
	}
	
	/**
	 * A comma-separated list of email recipient that will be used for every trigger.
	 */
	public String recipientList;

	/** This is the list of email triggers that the project has configured */
	private List<EmailTrigger> configuredTriggers = new ArrayList<EmailTrigger>();

	/**
	 * The contentType of the emails for this project (text/html, text/plain, etc).
	 */
	public String contentType;

	/**
     * The charset of the emails for this project.
     */
    public String charset;

	/**
	 * The default subject of the emails for this project.  ($PROJECT_DEFAULT_SUBJECT)
	 */
	public String defaultSubject;

	/**
	 * The default body of the emails for this project.  ($PROJECT_DEFAULT_BODY)
	 */
	public String defaultContent;
	
	public boolean defaultContentIsScript;

    public String buildForTesting;

	/**
	 * Get the list of configured email triggers for this project.
	 */
	public List<EmailTrigger> getConfiguredTriggers() {
		if(configuredTriggers == null)
			configuredTriggers = new ArrayList<EmailTrigger>();
		return configuredTriggers;
	}

	/**
	 * Get the list of non-configured email triggers for this project.
	 */
	public List<EmailTrigger> getNonConfiguredTriggers() {
		List<EmailTrigger> confTriggers = getConfiguredTriggers();
		
		List<EmailTrigger> retList = new ArrayList<EmailTrigger>();
		for(String mailerId : EMAIL_TRIGGER_TYPE_MAP.keySet()) {
			boolean contains = false;
			for(EmailTrigger trigger : confTriggers) {
				if(trigger.getDescriptor().getMailerId().equals(mailerId)) {
					contains = true;
					break;
				}
			}
			if(!contains) {
				retList.add(EMAIL_TRIGGER_TYPE_MAP.get(mailerId).getNewInstance(null));
			}
		}
		return retList;
	}

	/**
	 * Return true if the project has been configured, otherwise returns false
	 */
	public boolean isConfigured() {
		return !getConfiguredTriggers().isEmpty();
	}
	
	/**
	 * Return true if the project has been configured, otherwise returns false
	 */
	public boolean getConfigured() {
		return isConfigured();
	}

	@Override
	public boolean prebuild(AbstractBuild<?,?> build, BuildListener listener) {
		return _perform(build,listener,true);
	}

	@Override
	public boolean perform(AbstractBuild<?,?> build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
		return _perform(build,listener,false);
	}
	
	private boolean _perform(AbstractBuild<?,?> build, BuildListener listener, boolean forPreBuild) {
	   	boolean emailTriggered = false;
		
	   	Map<String,EmailTrigger> triggered = new HashMap<String, EmailTrigger>();
	   	
		for(EmailTrigger trigger : configuredTriggers) {
			if(trigger.isPreBuild() == forPreBuild && trigger.trigger((AbstractBuild)build)) {
				String tName = trigger.getDescriptor().getTriggerName();
				triggered.put(tName,trigger);
				listener.getLogger().println("Email was triggered for: " + tName);
				emailTriggered = true;
			}
		}
		
		//Go through and remove triggers that are replaced by others
		List<String> replacedTriggers = new ArrayList<String>();
		
		for(String triggerName : triggered.keySet()) {
			replacedTriggers.addAll(triggered.get(triggerName).getDescriptor().getTriggerReplaceList());
		}
		for(String triggerName : replacedTriggers) {
			triggered.remove(triggerName);
			listener.getLogger().println("Trigger " + triggerName + " was overridden by another trigger and will not send an email.");
		}
		
		if(emailTriggered && triggered.isEmpty()) {
			listener.getLogger().println("There is a circular trigger replacement with the email triggers.  No email is sent.");
			return false;
		}
		else if(triggered.isEmpty()) {
			listener.getLogger().println("No emails were triggered.");
			return true;
		}
		
		for(String triggerName :triggered.keySet()) {
			listener.getLogger().println("Sending email for trigger: " + triggerName);
			sendMail(triggered.get(triggerName).getEmail(), build, listener);
		}
		
		return true;
	}
	
	private boolean sendMail(EmailType mailType, AbstractBuild<?,?> build, BuildListener listener) {
		try {
			MimeMessage msg = createMail(mailType, build, listener);
			Address[] allRecipients = msg.getAllRecipients();
			if (allRecipients != null) {
				StringBuilder buf = new StringBuilder("Sending email to:");
				for (Address a : allRecipients)
					buf.append(' ').append(a);
				listener.getLogger().println(buf);
				Transport.send(msg);
				if (build.getAction(MailMessageIdAction.class) == null)
					build.addAction(new MailMessageIdAction(msg.getMessageID()));
				return true;
			} else {
				listener.getLogger().println("An attempt to send an e-mail"
					+ " to empty list of recipients, ignored.");
			}
		} catch(MessagingException e) {
			LOGGER.log(Level.WARNING, "Could not send email.",e);
			e.printStackTrace(listener.error("Could not send email as a part of the post-build publishers."));
		}
		
		return false;
	}

	private MimeMessage createMail(EmailType type, AbstractBuild<?,?> build, BuildListener listener) throws MessagingException {
		boolean overrideGlobalSettings = ExtendedEmailPublisher.DESCRIPTOR.getOverrideGlobalSettings();

		MimeMessage msg;
		
		// If not overriding global settings, use the Mailer class to create a session and set the from address
		// Else we'll do it ourselves
		if (!overrideGlobalSettings) {
			msg = new MimeMessage(Mailer.descriptor().createSession());
			msg.setFrom(new InternetAddress(Mailer.descriptor().getAdminAddress()));
		} else {
			msg = new MimeMessage(ExtendedEmailPublisher.DESCRIPTOR.createSession());
			msg.setFrom(new InternetAddress(ExtendedEmailPublisher.DESCRIPTOR.getAdminAddress()));
		}

		//Set the contents of the email
        msg.setSentDate(new Date());

        setSubject( type, build, msg );

        setContent( type, build, msg );

		// Get the recipients from the global list of addresses
		List<InternetAddress> recipientAddresses = new ArrayList<InternetAddress>();
		if (type.getSendToRecipientList()) {
			for (String recipient : recipientList.split(COMMA_SEPARATED_SPLIT_REGEXP)) {
				addAddress(recipientAddresses, recipient, listener);
			}
		}
		// Get the list of developers who made changes between this build and the last
		// if this mail type is configured that way
		if (type.getSendToDevelopers()) {
			Set<User> users;
			if (type.getIncludeCulprits()) {
				users = build.getCulprits();
			} else {
				users = new HashSet<User>();
				for (Entry change : build.getChangeSet()) {
					users.add(change.getAuthor());
				}
			}
			for (User user : users) {
				String adrs = user.getProperty(Mailer.UserProperty.class).getAddress();
				if (adrs != null)
					addAddress(recipientAddresses, adrs, listener);
				else {
					listener.getLogger().println("Failed to send e-mail to " + user.getFullName() + " because no e-mail address is known, and no default e-mail domain is configured");
				}
			}
		}
		//Get the list of recipients that are uniquely specified for this type of email
		if (type.getRecipientList() != null && type.getRecipientList().trim().length() > 0) {
			String[] typeRecipients = type.getRecipientList().split(COMMA_SEPARATED_SPLIT_REGEXP);
			for (int i = 0; i < typeRecipients.length; i++) {
				recipientAddresses.add(new InternetAddress(typeRecipients[i]));
			}
		}
		
		msg.setRecipients(Message.RecipientType.TO, recipientAddresses.toArray(new InternetAddress[recipientAddresses.size()]));

		AbstractBuild<?,?> pb = build.getPreviousBuild();
		if (pb!=null) {
			// Send mails as replies until next successful build
			MailMessageIdAction b = pb.getAction(MailMessageIdAction.class);
			if(b!=null && pb.getResult()!=Result.SUCCESS) {
				msg.setHeader("In-Reply-To",b.messageId);
				msg.setHeader("References",b.messageId);
			}
		}

		return msg;
	}

    private String getCharset() {
        String cs = charset;
        if (cs == null || DEFAULT_CHARSET_SENTINAL.equalsIgnoreCase(cs)) {
            cs = DESCRIPTOR.getDefaultCharset();
        }
        if (cs == null || DEFAULT_CHARSET_SENTINAL.equalsIgnoreCase(cs)) {
            return CHARSET;
        } else {
            return cs;
        }
    }


    private void setSubject( final EmailType type, final AbstractBuild<?, ?> build, MimeMessage msg )
        throws MessagingException
    {
        String subject = new ContentBuilder().transformText(type.getSubject(), this, type, (AbstractBuild)build);
        msg.setSubject(subject, getCharset());
    }

    private void setContent( final EmailType type, final AbstractBuild<?, ?> build, MimeMessage msg )
        throws MessagingException
    {
        final String text = new ContentBuilder().transformText(type.getBody(), this, type, (AbstractBuild)build);

        String messageContentType = contentType;
        // contentType is null if the project was not reconfigured after upgrading.
        if (messageContentType == null || "default".equals(messageContentType)) {
            messageContentType = DESCRIPTOR.getDefaultContentType();
            // The defaultContentType is null if the main Hudson configuration
            // was not reconfigured after upgrading.
            if (messageContentType == null) {
                messageContentType = "text/plain";
            }
        }
        messageContentType += "; charset=" + getCharset();

        msg.setContent(text, messageContentType);
    }

    private static void addAddress(List<InternetAddress> addresses, String address, BuildListener listener) {
		try {
			addresses.add(new InternetAddress(address));
		} catch(AddressException ae) {
			LOGGER.log(Level.WARNING, "Could not create email address.", ae);
			listener.getLogger().println("Failed to create e-mail address for " + address);
		}
	}
	
	@Override
	public boolean needsToRunAfterFinalized() {
		return true;
	}

	public BuildStepMonitor getRequiredMonitorService() {
		return BuildStepMonitor.BUILD;
	}

	@Override
	public BuildStepDescriptor<Publisher> getDescriptor() {
		return DESCRIPTOR;
	}
	
	@Extension
	public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

	/*
	 * These settings are the settings that are global.
	 */
	public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {
		/**
		 * The default e-mail address suffix appended to the user name found from changelog,
		 * to send e-mails. Null if not configured.
		 */
		private String defaultSuffix;

		/**
		 * Hudson's own URL, to put into the e-mail.
		 */
		private String hudsonUrl;

		/**
		 * If non-null, use SMTP-AUTH with these information.
		 */
		private String smtpAuthPassword,smtpAuthUsername;

		/**
		 * The e-mail address that Hudson puts to "From:" field in outgoing e-mails.
		 * Null if not configured.
		 */
		private String adminAddress;

		/**
		 * The SMTP server to use for sending e-mail. Null for default to the environment,
		 * which is usually <tt>localhost</tt>.
		 */
		private String smtpHost;
		
		/**
		 * If true use SSL on port 465 (standard SMTPS) unless <code>smtpPort</code> is set.
		 */
		private boolean useSsl;
		
		/**
		 * The SMTP port to use for sending e-mail. Null for default to the environment,
		 * which is usually <tt>25</tt>.
		 */
		private String smtpPort;
		
		/**
		 * This is a global default content type (mime type) for emails.
		 */
		private String defaultContentType;

		/**
         * This is a global default charset (mime type) for emails.
         */
        private String defaultCharset;

		/**
		 * This is a global default subject line for sending emails.
		 */
		private String defaultSubject;
		
		/**
		 * This is a global default body for sending emails.
		 */
		private String defaultBody;

        /**
         * This indicates that the global default body or subject line should be evaluated as a script.
         */
        private boolean defaultIsScript;

        /**
         * This just remembers the last build for testing that was saved, for the user's convenience.
         */
        public String defaultBuildForTesting;

		private boolean overrideGlobalSettings;

        @Override
		public String getDisplayName() {
			return "Editable Email Notification";
		}
		
		public String getAdminAddress() {
			String v = adminAddress;
			if (v == null) {
				v = "address not configured yet <nobody>";
			}
			return v;
		}

		public String getDefaultSuffix() {
			return defaultSuffix;
		}
		
		/** JavaMail session. */
		public Session createSession() {
			/*
			 * 				Mailer.DescriptorImpl desc = Mailer.descriptor();
				smtpHost = nullify(desc.getSmtpServer());
				adminAddress = desc.getAdminAddress();
				defaultSuffix = nullify(desc.getDefaultSuffix());
				hudsonUrl = desc.getUrl();
				smtpAuthUsername = desc.getSmtpAuthUserName();
				smtpAuthPassword = desc.getSmtpAuthPassword();
				useSsl = desc.getUseSsl();
				smtpPort = desc.getSmtpPort();
			 */
			Properties props = new Properties(System.getProperties());
			if(smtpHost!=null)
				props.put("mail.smtp.host",smtpHost);
			if (smtpPort!=null) {
				props.put("mail.smtp.port", smtpPort);
			}
			if (useSsl) {
				/* This allows the user to override settings by setting system properties but
				 * also allows us to use the default SMTPs port of 465 if no port is already set.
				 * It would be cleaner to use smtps, but that's done by calling session.getTransport()...
				 * and thats done in mail sender, and it would be a bit of a hack to get it all to
				 * coordinate, and we can make it work through setting mail.smtp properties.
				 */
				if (props.getProperty("mail.smtp.socketFactory.port") == null) {
					String port = smtpPort==null?"465":smtpPort;
					props.put("mail.smtp.port", port);
					props.put("mail.smtp.socketFactory.port", port);
				}
				if (props.getProperty("mail.smtp.socketFactory.class") == null) {
					props.put("mail.smtp.socketFactory.class","javax.net.ssl.SSLSocketFactory");
				}
				props.put("mail.smtp.socketFactory.fallback", "false");
			}
			if (smtpAuthUsername!=null)
				props.put("mail.smtp.auth","true");
			return Session.getInstance(props,getAuthenticator());
		}
		
		private Authenticator getAuthenticator() {
			final String un = getSmtpAuthUsername();
			if (un == null) return null;
			return new Authenticator() {
				@Override
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(getSmtpAuthUsername(), getSmtpAuthPassword());
				}
			};
		}

		public String getHudsonUrl() {
			if (hudsonUrl == null) {
				return Hudson.getInstance().getRootUrl();
			}
			return hudsonUrl;
		}

		public String getSmtpServer() {
			return smtpHost;
		}

		public String getSmtpAuthUsername() {
			return smtpAuthUsername;
		}
		
		public String getSmtpAuthPassword() {
			return smtpAuthPassword;
		}

		public boolean getUseSsl() {
			return useSsl;
		}
		
		public String getSmtpPort() {
			return smtpPort;
		}

        public String getDefaultContentType() {
            return defaultContentType;
        }

        public String getDefaultCharset() {
			return defaultCharset;
		}

        public String getDefaultSubject() {
			return defaultSubject;
		}
		
		public String getDefaultBody() {
			return defaultBody;
		}

        public boolean getDefaultIsScript() {
            return defaultIsScript;
        }

        public String getDefaultBuildForTesting() {
            return defaultBuildForTesting;
        }
		
		public boolean getOverrideGlobalSettings() {
			return overrideGlobalSettings;
		}

		public boolean isApplicable(Class<? extends AbstractProject> jobType) {
			return true;
                }

		@Override
		public Publisher newInstance(StaplerRequest req, JSONObject formData) throws hudson.model.Descriptor.FormException {
			// Save the recipient lists
			String listRecipients = formData.getString("recipientlist_recipients");
			
			// Save configuration for each trigger type
			ExtendedEmailPublisher m = new ExtendedEmailPublisher();
			m.recipientList = listRecipients;
			m.contentType = formData.getString("project_content_type");
			m.charset = formData.getString("project_charset");
            m.defaultSubject = formData.getString("project_default_subject");
			m.defaultContent = formData.getString("project_default_content");
            m.defaultContentIsScript = formData.optBoolean("project_default_content_is_script");
			m.configuredTriggers = new ArrayList<EmailTrigger>();
            m.buildForTesting = req.getParameter("project_build_for_testing");           
            
			// Create a new email trigger for each one that is configured
			for (String mailerId : EMAIL_TRIGGER_TYPE_MAP.keySet()) {
				if("true".equalsIgnoreCase(formData.optString("mailer_" + mailerId + "_configured"))) {
					EmailType type = createMailType(formData, mailerId);
					EmailTrigger trigger = EMAIL_TRIGGER_TYPE_MAP.get(mailerId).getNewInstance(type);
					m.configuredTriggers.add(trigger);
				}
			}
			
			req.bindParameters(m, "ext_mailer_");
			return m;
		}
		
		private EmailType createMailType(JSONObject formData, String mailType) {
			EmailType m = new EmailType();
			String prefix = "mailer_" + mailType + '_';
			m.setSubject(formData.getString(prefix + "subject"));
			m.setBody(formData.getString(prefix + "body"));
			m.setRecipientList(formData.getString(prefix + "recipientList"));
			m.setSendToRecipientList(formData.optBoolean(prefix + "sendToRecipientList"));
			m.setSendToDevelopers(formData.optBoolean(prefix + "sendToDevelopers"));
			m.setIncludeCulprits(formData.optBoolean(prefix + "includeCulprits"));
            m.setScript(formData.optBoolean(prefix + "script"));
			return m;
		}
		
		public DescriptorImpl() {
			super(ExtendedEmailPublisher.class);
			load();
			if (defaultBody == null && defaultSubject == null) {
				defaultBody = DEFAULT_BODY_TEXT;
				defaultSubject = DEFAULT_SUBJECT_TEXT;
			}
		}

		@Override
		public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
			// Most of this stuff is the same as the built-in email publisher

			// Configure the smtp server
			smtpHost = nullify(req.getParameter("ext_mailer_smtp_server"));
			adminAddress = req.getParameter("ext_mailer_admin_address");
			defaultSuffix = nullify(req.getParameter("ext_mailer_default_suffix"));
			
			// Specify the url to this hudson instance
			String url = nullify(req.getParameter("ext_mailer_hudson_url"));
			if (url != null && !url.endsWith("/")) {
				url += '/';
			}
			if (url == null) {
				url = Hudson.getInstance().getRootUrl();
			}
			hudsonUrl = url;

			// specify authentication information
			if (req.getParameter("extmailer.useSMTPAuth") != null) {
				smtpAuthUsername = nullify(req.getParameter("extmailer.SMTPAuth.userName"));
				smtpAuthPassword = nullify(req.getParameter("extmailer.SMTPAuth.password"));
			} else {
				smtpAuthUsername = smtpAuthPassword = null;
			}
			
			// specify if the mail server uses ssl for authentication
			useSsl = req.getParameter("ext_mailer_smtp_use_ssl") != null;
			
			// specify custom smtp port
			smtpPort = nullify(req.getParameter("ext_mailer_smtp_port"));
			
			defaultContentType = nullify(req.getParameter("ext_mailer_default_content_type"));
            defaultCharset = nullify(req.getParameter("ext_mailer_default_charset"));

			// Allow global defaults to be set for the subject and body of the email
			defaultSubject = nullify(req.getParameter("ext_mailer_default_subject"));
			defaultBody = nullify(req.getParameter("ext_mailer_default_body"));
            defaultIsScript = req.getParameter("ext_mailer_default_is_script") != null;
            defaultBuildForTesting = req.getParameter("ext_mailer_default_build_for_testing");

			overrideGlobalSettings = req.getParameter("ext_mailer_use_global_settings") != null;
			
			save();
			return super.configure(req, formData);
		}
		
		private String nullify(String v) {
			if(v!=null && v.length()==0)
				v=null;
			return v;
		}
		
		@Override
		public String getHelpFile() {
			return "/plugin/email-ext/help/main.html";
		}
		
		public FormValidation doAddressCheck(
				@QueryParameter final String value) throws IOException, ServletException {
			try {
				new InternetAddress(value);
				return FormValidation.ok();
			} catch (AddressException e) {
				return FormValidation.error(e.getMessage());
			}
		}
		
		public FormValidation doRecipientListRecipientsCheck(
				@QueryParameter final String value) throws IOException, ServletException {
			if(value != null && value.trim().length() > 0) {
				String[] names = value.split(COMMA_SEPARATED_SPLIT_REGEXP);
				try {
					for(int i=0;i<names.length;i++) {
						if(names[i].trim().length()>0) {
							new InternetAddress(names[i]);
						}
					}
				}
				catch(AddressException e) {
					return FormValidation.error(e.getMessage());
				}
			}
			return FormValidation.ok();
		}

        public FormValidation doCharsetCheck(StaplerRequest req, StaplerResponse rsp, @QueryParameter final String value) throws IOException, ServletException {
            String charset = nullify(value);
            if (charset == null || DEFAULT_CHARSET_SENTINAL.equalsIgnoreCase(charset) || Charset.isSupported(charset)) {
                return FormValidation.ok();
            } else {
                return FormValidation.error("unsupported charset");
            }
        }

        public FormValidation doBuildForTestingCheck(StaplerRequest req, StaplerResponse rsp, @QueryParameter final String value) throws IOException, ServletException {
            String buildForTesting = nullify(value);
            if (buildForTesting == null) {
                return FormValidation.ok();
            }
            try {
                getBuildForTesting(buildForTesting);
                return FormValidation.ok();
            }
            catch (FormValidation e) {
                return e;
            }
        }

        private interface TransformStrategy {
            String transformText(String origText, ExtendedEmailPublisher publisher, EmailType type, AbstractBuild build);
        }

        public FormValidation doTestAgainstBuild(StaplerRequest req, @QueryParameter("project_build_for_testing") String buildForTesting) throws IOException {
            TransformStrategy strategy = new TransformStrategy() {
                public String transformText(String origText, ExtendedEmailPublisher publisher, EmailType type, AbstractBuild build) {
                    return new ContentBuilder().transformText(origText, publisher, type, build);
                }
            };
            return doTestAgainstBuild(strategy, PROJECT_DEFAULT_SUBJECT_TEXT, PROJECT_DEFAULT_BODY_TEXT, req, buildForTesting);
        }

        public FormValidation doGlobalTestAgainstBuild(StaplerRequest req,
                                                       @QueryParameter("ext_mailer_default_build_for_testing") String buildForTesting,
                                                       @QueryParameter("ext_mailer_default_is_script") final boolean globalIsScript,
                                                       @QueryParameter("ext_mailer_default_subject") String globalSubject,
                                                       @QueryParameter("ext_mailer_default_body") String globalBody
        ) throws IOException {
            TransformStrategy strategy = new TransformStrategy() {
                public String transformText(String origText, ExtendedEmailPublisher publisher, EmailType type, AbstractBuild build) {
                    // This works around ContentBuilder.transformText()'s static access of the global subject and body,
                    // which has not been updated before testing.
                    return new ContentBuilder().transformResolvedText(globalIsScript, origText, publisher, type, build);
                }
            };
            return doTestAgainstBuild(strategy, globalSubject, globalBody, req, buildForTesting);
        }

        private String testedEmailText;

        private FormValidation doTestAgainstBuild(TransformStrategy strategy,
                                                  String originalSubject,
                                                  String originalBody,
                                                  StaplerRequest req,
                                                  String buildForTesting
        ) throws IOException {
            buildForTesting = nullify(buildForTesting);
            if (buildForTesting == null) {
                return FormValidation.error("need to configure a build for testing");
            }
            try {
                AbstractBuild build = getBuildForTesting(buildForTesting);
                ExtendedEmailPublisher publisher = (ExtendedEmailPublisher) newInstance(req, null);
                EmailType type = new EmailType();
                type.setBody(ExtendedEmailPublisher.PROJECT_DEFAULT_BODY_TEXT);
                type.setSubject(ExtendedEmailPublisher.PROJECT_DEFAULT_SUBJECT_TEXT);
                String subject = strategy.transformText(originalSubject, publisher, type, build);
                testedEmailText = strategy.transformText(originalBody, publisher, type, build);
                String resultUrl = req.getRequestURI().replace("testAgainstBuild", "testedEmailText")
                        .replace("globalTestAgainstBuild", "testedEmailText"); // todo: some better hack
                return FormValidation.okWithMarkup("resulting subject: " + subject
                        + "<br/>resulting body:<br/> <iframe width='100%' height='400px' src='" + resultUrl + "'/>");
            }
            catch (FormValidation e) {
                return e;
            } catch (FormException e) {
                return FormValidation.error(e.getMessage());
            }
        }

        public void doTestedEmailText(StaplerRequest req, StaplerResponse rsp) throws IOException {
            rsp.setContentType("text/html");
            rsp.getWriter().write(testedEmailText);
        }

        private AbstractBuild getBuildForTesting(String buildForTesting) throws FormValidation {
            int slashIndex = buildForTesting.indexOf('/');
            if (slashIndex == -1) {
                throw FormValidation.error("must format as '<jobName>/<buildNumber>'");
            }
            String jobName = buildForTesting.substring(0, slashIndex);
            String buildNumber = buildForTesting.substring(slashIndex + 1);
            Job job;
            try {
                job = (Job) Hudson.getInstance().getItem(jobName);
            }
            catch (ClassCastException e) {
                throw FormValidation.error(jobName + " is not a job");
            }
            if (job == null) {
                throw FormValidation.error(jobName + " job not found");
            }
            AbstractBuild build;
            try {
                build = (AbstractBuild) job.getBuildByNumber(Integer.valueOf(buildNumber));
            }
            catch (NumberFormatException e) {
                throw FormValidation.error("cannot parse build number: " + e.getMessage());
            }
            catch (ClassCastException e) {
                throw FormValidation.error("not a build: " + e.getMessage());
            }
            if (build == null) {
                throw FormValidation.error("build " + buildNumber + " not found");
            }
            return build;
        }
	}



}
