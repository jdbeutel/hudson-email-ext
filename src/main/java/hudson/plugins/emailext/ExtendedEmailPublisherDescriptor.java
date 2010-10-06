package hudson.plugins.emailext;

import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.Hudson;
import hudson.model.Job;
import hudson.plugins.emailext.plugins.ContentBuilder;
import hudson.plugins.emailext.plugins.EmailTrigger;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.Secret;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.servlet.ServletException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Properties;

/**
 * These settings are global configurations
 */
public class ExtendedEmailPublisherDescriptor
    extends BuildStepDescriptor<Publisher>
{
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
     * If non-null, use SMTP-AUTH
     */
    private String smtpAuthUsername;

    private Secret smtpAuthPassword;

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
    public String getDisplayName()
    {
        return "Editable Email Notification";
    }

    public String getAdminAddress()
    {
        String v = adminAddress;
        if ( v == null )
        {
            v = "address not configured yet <nobody>";
        }
        return v;
    }

    public String getDefaultSuffix()
    {
        return defaultSuffix;
    }

    public String getDefaultCharset()
    {
    	return defaultCharset;
    }

    /**
     * JavaMail session.
     */
    public Session createSession()
    {
        Properties props = new Properties( System.getProperties() );
        if ( smtpHost != null )
        {
            props.put( "mail.smtp.host", smtpHost );
        }
        if ( smtpPort != null )
        {
            props.put( "mail.smtp.port", smtpPort );
        }
        if ( useSsl )
        {
            /* This allows the user to override settings by setting system properties but
                    * also allows us to use the default SMTPs port of 465 if no port is already set.
                    * It would be cleaner to use smtps, but that's done by calling session.getTransport()...
                    * and thats done in mail sender, and it would be a bit of a hack to get it all to
                    * coordinate, and we can make it work through setting mail.smtp properties.
                    */
            if ( props.getProperty( "mail.smtp.socketFactory.port" ) == null )
            {
                String port = smtpPort == null ? "465" : smtpPort;
                props.put( "mail.smtp.port", port );
                props.put( "mail.smtp.socketFactory.port", port );
            }
            if ( props.getProperty( "mail.smtp.socketFactory.class" ) == null )
            {
                props.put( "mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory" );
            }
            props.put( "mail.smtp.socketFactory.fallback", "false" );
        }
        if ( smtpAuthUsername != null )
        {
            props.put( "mail.smtp.auth", "true" );
        }
        return Session.getInstance( props, getAuthenticator() );
    }

    private Authenticator getAuthenticator()
    {
        final String un = getSmtpAuthUsername();
        if ( un == null )
        {
            return null;
        }
        return new Authenticator()
        {
            @Override
            protected PasswordAuthentication getPasswordAuthentication()
            {
                return new PasswordAuthentication( getSmtpAuthUsername(), getSmtpAuthPassword() );
            }
        };
    }

    public String getHudsonUrl()
    {
        return hudsonUrl != null ? hudsonUrl : Hudson.getInstance().getRootUrl();
    }

    public String getSmtpServer()
    {
        return smtpHost;
    }

    public String getSmtpAuthUsername()
    {
        return smtpAuthUsername;
    }

    public String getSmtpAuthPassword()
    {
        return Secret.toString( smtpAuthPassword );
    }

    public boolean getUseSsl()
    {
        return useSsl;
    }

    public String getSmtpPort()
    {
        return smtpPort;
    }

    public String getDefaultContentType()
    {
        return defaultContentType;
    }

    public String getDefaultSubject()
    {
        return defaultSubject;
    }

    public String getDefaultBody()
    {
        return defaultBody;
    }

    public boolean getDefaultIsScript() {
        return defaultIsScript;
    }

    public String getDefaultBuildForTesting() {
        return defaultBuildForTesting;
    }

    public boolean getOverrideGlobalSettings()
    {
        return overrideGlobalSettings;
    }

    public boolean isApplicable( Class<? extends AbstractProject> jobType )
    {
        return true;
    }

    @Override
    public Publisher newInstance( StaplerRequest req, JSONObject formData )
        throws hudson.model.Descriptor.FormException
    {
        // Save the recipient lists
        String listRecipients = formData.getString( "recipientlist_recipients" );

        // Save configuration for each trigger type
        ExtendedEmailPublisher m = new ExtendedEmailPublisher();
        m.recipientList = listRecipients;
        m.contentType = formData.getString( "project_content_type" );
        m.charset = formData.getString("project_charset");
        m.defaultSubject = formData.getString( "project_default_subject" );
        m.defaultContent = formData.getString( "project_default_content" );
        m.defaultContentIsScript = formData.optBoolean("project_default_content_is_script");
        m.buildForTesting = formData.getString("project_build_for_testing");
        m.configuredTriggers = new ArrayList<EmailTrigger>();

        // Create a new email trigger for each one that is configured
        for ( String mailerId : ExtendedEmailPublisher.EMAIL_TRIGGER_TYPE_MAP.keySet() )
        {
            if ( "true".equalsIgnoreCase( formData.optString( "mailer_" + mailerId + "_configured" ) ) )
            {
                EmailType type = createMailType( formData, mailerId );
                EmailTrigger trigger = ExtendedEmailPublisher.EMAIL_TRIGGER_TYPE_MAP.get( mailerId ).getNewInstance( type );
                m.configuredTriggers.add( trigger );
            }
        }

        return m;
    }

    private EmailType createMailType( JSONObject formData, String mailType )
    {
        EmailType m = new EmailType();
        String prefix = "mailer_" + mailType + '_';
        m.setSubject( formData.getString( prefix + "subject" ) );
        m.setBody( formData.getString( prefix + "body" ) );
        m.setRecipientList( formData.getString( prefix + "recipientList" ) );
        m.setSendToRecipientList( formData.optBoolean( prefix + "sendToRecipientList" ) );
        m.setSendToDevelopers( formData.optBoolean( prefix + "sendToDevelopers" ) );
        m.setIncludeCulprits( formData.optBoolean( prefix + "includeCulprits" ) );
        return m;
    }

    public ExtendedEmailPublisherDescriptor()
    {
        super( ExtendedEmailPublisher.class );
        load();
        if ( defaultBody == null && defaultSubject == null )
        {
            defaultBody = ExtendedEmailPublisher.DEFAULT_BODY_TEXT;
            defaultSubject = ExtendedEmailPublisher.DEFAULT_SUBJECT_TEXT;
        }
    }

    @Override
    public boolean configure( StaplerRequest req, JSONObject formData )
        throws FormException
    {
        // Most of this stuff is the same as the built-in email publisher

        // Configure the smtp server
        smtpHost = nullify( req.getParameter( "ext_mailer_smtp_server" ) );
        adminAddress = req.getParameter( "ext_mailer_admin_address" );
        defaultSuffix = nullify( req.getParameter( "ext_mailer_default_suffix" ) );

        // Specify the url to this hudson instance
        String url = nullify( req.getParameter( "ext_mailer_hudson_url" ) );
        if ( url != null && !url.endsWith( "/" ) )
        {
            url += '/';
        }
        if ( url == null )
        {
            url = Hudson.getInstance().getRootUrl();
        }
        hudsonUrl = url;

        // specify authentication information
        if ( req.getParameter( "extmailer.useSMTPAuth" ) != null )
        {
            smtpAuthUsername = nullify( req.getParameter( "extmailer.SMTPAuth.userName" ) );
            smtpAuthPassword = Secret.fromString( nullify( req.getParameter( "extmailer.SMTPAuth.password" ) ) );
        }
        else
        {
            smtpAuthUsername = null;
            smtpAuthPassword = null;
        }

        // specify if the mail server uses ssl for authentication
        useSsl = req.getParameter( "ext_mailer_smtp_use_ssl" ) != null;

        // specify custom smtp port
        smtpPort = nullify( req.getParameter( "ext_mailer_smtp_port" ) );

        defaultContentType = nullify( req.getParameter( "ext_mailer_default_content_type" ) );
        defaultCharset = nullify(req.getParameter("ext_mailer_default_charset"));

        // Allow global defaults to be set for the subject and body of the email
        defaultSubject = nullify( req.getParameter( "ext_mailer_default_subject" ) );
        defaultBody = nullify( req.getParameter( "ext_mailer_default_body" ) );
        defaultIsScript = req.getParameter("ext_mailer_default_is_script") != null;
        defaultBuildForTesting = req.getParameter("ext_mailer_default_build_for_testing");

        overrideGlobalSettings = req.getParameter( "ext_mailer_override_global_settings" ) != null;

        save();
        return super.configure( req, formData );
    }

    private String nullify( String v )
    {
        if ( v != null && v.length() == 0 )
        {
            v = null;
        }
        return v;
    }

    @Override
    public String getHelpFile()
    {
        return "/plugin/email-ext/help/main.html";
    }

    public FormValidation doAddressCheck( @QueryParameter final String value )
        throws IOException, ServletException
    {
        try
        {
            new InternetAddress( value );
            return FormValidation.ok();
        }
        catch ( AddressException e )
        {
            return FormValidation.error( e.getMessage() );
        }
    }

    public FormValidation doRecipientListRecipientsCheck( @QueryParameter final String value )
        throws IOException, ServletException
    {
        return new EmailRecepientUtils().validateFormRecipientList( value );
	}

    public FormValidation doCharsetCheck(StaplerRequest req, StaplerResponse rsp, @QueryParameter final String value) throws IOException, ServletException {
        String charset = nullify(value);
        if (charset == null || ExtendedEmailPublisher.DEFAULT_CHARSET_SENTINAL.equalsIgnoreCase(charset) || Charset.isSupported(charset)) {
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

    // validateButton in config.jelly
    public FormValidation doTestAgainstBuild(StaplerRequest req) throws IOException, ServletException {
        ExtendedEmailPublisher publisher = new ExtendedEmailPublisher();
        publisher.contentType = req.getParameter("project_content_type");
        publisher.charset = req.getParameter("project_charset");
        publisher.defaultSubject = req.getParameter("project_default_subject");
        publisher.defaultContent = req.getParameter("project_default_content");
        publisher.defaultContentIsScript = Boolean.valueOf(req.getParameter("project_default_content_is_script"));
        publisher.buildForTesting = req.getParameter("project_build_for_testing");
        return doTestAgainstBuild(publisher, false, req);
    }

    // validateButton in global.jelly
    public FormValidation doGlobalTestAgainstBuild(StaplerRequest req) throws IOException, ServletException {
        ExtendedEmailPublisher publisher = new ExtendedEmailPublisher();
        // testing at project level because the corresponding globals are static
        publisher.contentType = req.getParameter("ext_mailer_default_content_type");
        publisher.charset = req.getParameter("ext_mailer_default_charset");
        publisher.defaultSubject = req.getParameter("ext_mailer_default_subject");
        publisher.defaultContent = req.getParameter("ext_mailer_default_body");
        publisher.defaultContentIsScript = Boolean.valueOf(req.getParameter("ext_mailer_default_is_script"));
        publisher.buildForTesting = req.getParameter("ext_mailer_default_build_for_testing");
        return doTestAgainstBuild(publisher, true, req);
    }

	// for iframe callback
	private String testedEmailText;
	private String testedEmailContentType;

	private FormValidation doTestAgainstBuild(ExtendedEmailPublisher publisher,
			boolean globallyResolved, StaplerRequest req) throws FormValidation {
		if (nullify(publisher.buildForTesting) == null) {
			return FormValidation.error("need to specify a build for testing");
		}
		testedEmailContentType = publisher.getContentType();
		AbstractBuild build = getBuildForTesting(publisher.buildForTesting);
		String subject;
		if (globallyResolved) {
			// Work around ContentBuilder.transformText()'s static access of the
			// global subject and body,
			// which has not been updated before testing.
			subject = transformResolvedText(publisher.defaultSubject,
					publisher, build);
			testedEmailText = transformResolvedText(publisher.defaultContent,
					publisher, build);
		} else {
			// use default tokens to induce resolution for project-level script
			// flag
			subject = transformText(
					ExtendedEmailPublisher.PROJECT_DEFAULT_SUBJECT_TEXT,
					publisher, build);
			testedEmailText = transformText(
					ExtendedEmailPublisher.PROJECT_DEFAULT_BODY_TEXT,
					publisher, build);
		}
		String resultUrl = req.getRequestURI()
				.replace("testAgainstBuild", "testedEmailText")
				.replace("globalTestAgainstBuild", "testedEmailText"); // todo:
																		// something
																		// less
																		// hacky?
		return FormValidation
				.okWithMarkup("resulting subject: "
						+ subject // todo: subject charset?
						+ "<br/>resulting body:<br/> <iframe width='100%' height='400px' src='"
						+ resultUrl + "'/>");
	}

    private static String transformResolvedText(String text, ExtendedEmailPublisher publisher, AbstractBuild build) {
        return new ContentBuilder().transformResolvedText(publisher.defaultContentIsScript, text, publisher, new EmailType(), build);
    }

    private static String transformText(String text, ExtendedEmailPublisher publisher, AbstractBuild build) {
        return new ContentBuilder().transformText(text, publisher, new EmailType(), build);
    }

    // callback from iframe
    public void doTestedEmailText(StaplerRequest req, StaplerResponse rsp) throws IOException {
        rsp.setContentType(testedEmailContentType);
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
