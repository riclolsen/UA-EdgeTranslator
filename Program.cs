
namespace Opc.Ua.Edge.Translator
{
    using Opc.Ua;
    using Opc.Ua.Configuration;
    using Serilog;
    using System;
    using System.IO;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;

    public class Program
    {
        public static ApplicationInstance App { get; private set; }

        public static async Task Main()
        {
            // setup logging
            string pathToLogFile = Path.Combine(Directory.GetCurrentDirectory(), "logs");
            if (Environment.GetEnvironmentVariable("LOG_FILE_PATH") != null)
            {
                pathToLogFile = Environment.GetEnvironmentVariable("LOG_FILE_PATH");
            }
            InitLogging(pathToLogFile);

            // create OPC UA client app
            string appName = "UAEdgeTranslator";
            if (Environment.GetEnvironmentVariable("APP_NAME") != null)
            {
                appName = Environment.GetEnvironmentVariable("APP_NAME");
            }

            ApplicationInstance.MessageDlg = new ApplicationMessageDlg();
            App = new ApplicationInstance
            {
                ApplicationName = appName,
                ApplicationType = ApplicationType.ClientAndServer,
                ConfigSectionName = "Ua.Edge.Translator"
            };

            try
            {
                await App.LoadApplicationConfiguration(false).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log.Logger.Warning("Could not load configuration file, using defaults: " + ex.Message);

                // Create a minimal default configuration if the file failed to load
                App.ApplicationConfiguration = new ApplicationConfiguration
                {
                    ApplicationName = appName,
                    ApplicationUri = "urn:UAEdgeTranslator",
                    ProductUri = "http://opcfoundation.com/UA/EdgeTranslator",
                    ApplicationType = ApplicationType.ClientAndServer,
                    SecurityConfiguration = new SecurityConfiguration
                    {
                        ApplicationCertificate = new CertificateIdentifier
                        {
                            StoreType = "Directory",
                            StorePath = "./pki/own",
                            SubjectName = "CN=UAEdgeTranslator, O=OPC Foundation"
                        },
                        AutoAcceptUntrustedCertificates = true
                    },
                    ServerConfiguration = new ServerConfiguration
                    {
                        BaseAddresses = { "opc.tcp://localhost:4840/UA/UAEdgeTranslator" },
                        SecurityPolicies = {
                            new ServerSecurityPolicy {
                                SecurityMode = MessageSecurityMode.None,
                                SecurityPolicyUri = SecurityPolicies.None
                            }
                        },
                        UserTokenPolicies = {
                            new UserTokenPolicy {
                                TokenType = UserTokenType.UserName,
                                SecurityPolicyUri = SecurityPolicies.Basic256Sha256
                            },
                            new UserTokenPolicy {
                                TokenType = UserTokenType.Anonymous
                            }
                        },
                        ServerProfileArray = {
                            "http://opcfoundation.org/UA-Profile/Server/StandardUA2017",
                            "http://opcfoundation.org/UA-Profile/Server/DataAccess",
                            "http://opcfoundation.org/UA-Profile/Server/Methods"
                        }
                    },
                    ClientConfiguration = new ClientConfiguration
                    {
                        DefaultSessionTimeout = 15000
                    },
                    TransportQuotas = new TransportQuotas
                    {
                        OperationTimeout = 1200000,
                        MaxStringLength = 1048576,
                        MaxByteStringLength = 1048576,
                        MaxArrayLength = 1048576,
                        MaxMessageSize = 4194304,
                        MaxBufferSize = 65535,
                        ChannelLifetime = 600000,
                        SecurityTokenLifetime = 3600000
                    },
                    TraceConfiguration = new TraceConfiguration()
                };
            }

            if (App.ApplicationConfiguration.SecurityConfiguration == null)
            {
                App.ApplicationConfiguration.SecurityConfiguration = new SecurityConfiguration();
            }

            if (App.ApplicationConfiguration.ClientConfiguration == null)
            {
                App.ApplicationConfiguration.ClientConfiguration = new ClientConfiguration();
            }

            if (App.ApplicationConfiguration.SecurityConfiguration.ApplicationCertificate == null)
            {
                App.ApplicationConfiguration.SecurityConfiguration.ApplicationCertificate = new CertificateIdentifier();
            }

            if (string.IsNullOrEmpty(App.ApplicationConfiguration.SecurityConfiguration.ApplicationCertificate.StorePath))
            {
                App.ApplicationConfiguration.SecurityConfiguration.ApplicationCertificate.StoreType = "Directory";
                App.ApplicationConfiguration.SecurityConfiguration.ApplicationCertificate.StorePath = "./pki/own";
                App.ApplicationConfiguration.SecurityConfiguration.ApplicationCertificate.SubjectName = "CN=UAEdgeTranslator, O=OPC Foundation";
            }

            if (App.ApplicationConfiguration.TraceConfiguration == null)
            {
                App.ApplicationConfiguration.TraceConfiguration = new TraceConfiguration();
            }

            try
            {
                await App.CheckApplicationInstanceCertificate(false, 0).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log.Logger.Warning("Could not check application instance certificate: " + ex.Message);

                try
                {
                    // create a new certificate
                    await App.CheckApplicationInstanceCertificate(true, 0).ConfigureAwait(false);
                }
                catch (Exception ex2)
                {
                    Log.Logger.Error("Could not create application instance certificate: " + ex2.Message);
                }
            }

            // create OPC UA cert validator
            App.ApplicationConfiguration.CertificateValidator = new CertificateValidator();
            App.ApplicationConfiguration.CertificateValidator.CertificateValidation += new CertificateValidationEventHandler(OPCUAClientCertificateValidationCallback);
            App.ApplicationConfiguration.CertificateValidator.Update(App.ApplicationConfiguration).GetAwaiter().GetResult();

            string issuerPath = Path.Combine(Directory.GetCurrentDirectory(), "pki", "issuer", "certs");
            if (!Directory.Exists(issuerPath))
            {
                Directory.CreateDirectory(issuerPath);
            }

            Utils.Tracing.TraceEventHandler += new EventHandler<TraceEventArgs>(OpcStackLoggingHandler);

            // start the server
            await App.Start(new UAServer()).ConfigureAwait(false);

            Log.Logger.Information("UA Edge Translator is running.");
            await Task.Delay(Timeout.Infinite).ConfigureAwait(false);
        }

        private static void OPCUAClientCertificateValidationCallback(CertificateValidator sender, CertificateValidationEventArgs e)
        {
            // check if we have a trusted issuer cert yet
            bool provisioningMode = (Directory.EnumerateFiles(Path.Combine(Directory.GetCurrentDirectory(), "pki", "issuer", "certs")).Count() == 0);

            // we allow conections in provisoning mode, but limit access to the server
            if ((e.Error.StatusCode == StatusCodes.BadCertificateUntrusted) && provisioningMode)
            {
                Log.Logger.Warning("Auto-accepting certificate while in provisioning mode!");
                e.Accept = true;
            }
        }

        private static void OpcStackLoggingHandler(object sender, TraceEventArgs e)
        {
            if ((e.TraceMask & App.ApplicationConfiguration.TraceConfiguration.TraceMasks) != 0)
            {
                if (e.Exception != null)
                {
                    Log.Logger.Error(e.Exception, e.Format, e.Arguments);
                    return;
                }

                switch (e.TraceMask)
                {
                    case Utils.TraceMasks.StartStop:
                    case Utils.TraceMasks.Information: Log.Logger.Information(e.Format, e.Arguments); break;
                    case Utils.TraceMasks.Error: Log.Logger.Error(e.Format, e.Arguments); break;
                    case Utils.TraceMasks.StackTrace:
                    case Utils.TraceMasks.Security: Log.Logger.Warning(e.Format, e.Arguments); break;
                    default: Log.Logger.Verbose(e.Format, e.Arguments); break;
                }
            }
        }

        private static void InitLogging(string pathToLogFile)
        {
            LoggerConfiguration loggerConfiguration = new LoggerConfiguration();

#if DEBUG
            loggerConfiguration.MinimumLevel.Debug();
#else
            loggerConfiguration.MinimumLevel.Information();
#endif
            if (!Directory.Exists(pathToLogFile))
            {
                Directory.CreateDirectory(pathToLogFile);
            }

            // set logging sinks
            loggerConfiguration.WriteTo.Console();
            loggerConfiguration.WriteTo.File(Path.Combine(pathToLogFile, "uaedgetranslator.logfile.txt"), fileSizeLimitBytes: 1024 * 1024, rollOnFileSizeLimit: true, retainedFileCountLimit: 10);

            Log.Logger = loggerConfiguration.CreateLogger();
            Log.Logger.Information($"Log file is: {Path.Combine(pathToLogFile, "uaedgetranslator.logfile.txt")}");
        }
    }
}
