using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace Amazon.Utilities
{
    /// <summary>
    /// Utility class for working with AWS SAML.
    /// </summary>
    public class AwsSamlUtility : IDisposable
    {
        private IntPtr tokenHandle = IntPtr.Zero;
        private IntPtr dupeTokenHandle = IntPtr.Zero;
        private WindowsImpersonationContext windowsImpersonationContext;
        private bool disposed;

        /// <summary>
        /// Creates an instance of <see cref="AwsSamlUtility"/>.
        /// </summary>
        public AwsSamlUtility() : this(null, null, null)
        {

        }

        /// <summary>
        /// Creates an instance of <see cref="AwsSamlUtility"/> with the specified Windows credentials.
        /// </summary>
        /// <param name="userName">The username of the Windows user account.</param>
        /// <param name="password">The password of the Windows user account.</param>
        /// <param name="domain">The domain of the Windows user account.</param>
        public AwsSamlUtility(string userName, string password, string domain)
        {
            if (!string.IsNullOrWhiteSpace(userName) && !string.IsNullOrWhiteSpace(password) &&
                !string.IsNullOrWhiteSpace(domain))
            {
                ImpersonateUser(userName, password, domain);
            }
        }

        /// <summary>
        /// Gets the SAML assertion from the identity provider.
        /// </summary>
        /// <param name="identityProvider">The URI of the identity provider.</param>
        /// <returns>Returns the SAML assertion from the identity provider.</returns>
        public string GetSamlAssertion(string identityProvider)
        {
            var httpWebResponse = GetResult(identityProvider);

            using (var responseStream = httpWebResponse.GetResponseStream())
            {
                if (responseStream == null) return null;

                using (var streamReader = new StreamReader(responseStream))
                {
                    var data = streamReader.ReadToEnd();
                    var regex = new Regex(@"SAMLResponse\W+value\=""([^\""]+)\""");
                    var matches = regex.Matches(data);

                    string samlAssertion = null;
                    foreach (Match match in matches)
                    {
                        samlAssertion = match.Groups[1].Value;
                    }

                    return samlAssertion;
                }
            }
        }

        /// <summary>
        /// Gets a collection of roles based on the SAML assertion.
        /// </summary>
        /// <param name="samlAssertion">The SAML assertion provided by the identity provider.</param>
        /// <returns>Returns a collection of roles based on the SAML assertion.</returns>
        public IEnumerable<string> GetRoles(string samlAssertion)
        {
            if (string.IsNullOrWhiteSpace(samlAssertion))
            {
                throw new ArgumentException("The SAML assertion cannot be null, empty or consist of only white-space characters.");
            }

            const string namespacePrefix = "response";
            const string namespaceUrn = "urn:oasis:names:tc:SAML:2.0:assertion";
            const string xPathString = "//response:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']";

            var roles = new List<string>();
            var xmlDocument = new XmlDocument();

            var decoded = Convert.FromBase64String(samlAssertion);
            var deflated = Encoding.UTF8.GetString(decoded);
            xmlDocument.LoadXml(deflated);

            var xmlNamespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
            xmlNamespaceManager.AddNamespace(namespacePrefix, namespaceUrn);

            if (xmlDocument.DocumentElement == null) return roles;
            var roleAttributeNodes = xmlDocument.DocumentElement.SelectNodes(xPathString, xmlNamespaceManager);

            if (roleAttributeNodes == null || roleAttributeNodes.Count <= 0) return roles;

            var roleNodes = roleAttributeNodes[0].ChildNodes;
            for (var i = 0; i < roleNodes.Count; i++)
            {
                var roleNode = roleNodes[i];
                if (roleNode.InnerText.Length <= 0) continue;
                var chunks = roleNode.InnerText.Split(',');
                var role = chunks[0] + ',' + chunks[1];
                roles.Add(role);
            }

            return roles;
        }

        /// <summary>
        /// Gets the <see cref="SessionAWSCredentials"/> based on the specified SAML assertion and role.
        /// </summary>
        /// <param name="samlAssertion">The SAML assertion from the identity provider.</param>
        /// <param name="role">The role that the caller is assuming.</param>
        /// <param name="durationInSeconds">The duration for the AWS session credentials in seconds. Default value is 3600 seconds.</param>
        /// <returns>Returns a <see cref="SessionAWSCredentials"/> based on the specified SAML assertion and role.</returns>
        public SessionAWSCredentials GetSessionAwsCredentials(string samlAssertion, string role, int durationInSeconds = 3600)
        {
            var roles = role.Split(',');

            if (roles.Length > 1)
            {
                throw new ArgumentException("An invalid role was specified.");
            }

            var assumeRoleWithSamlRequest = new AssumeRoleWithSAMLRequest
            {
                SAMLAssertion = samlAssertion,
                PrincipalArn = roles[0],
                RoleArn = roles[1],
                DurationSeconds = durationInSeconds
            };

            // Need to create a  BasicAWSCredentials object and pass it to AmazonSecurityTokenServiceClient,
            // otherwise a null reference exception is thrown. Will need to look into this further as to why this happens.
            var basicCredential = new BasicAWSCredentials("", "");

            using (var amazonSecurityTokenServiceClient = new AmazonSecurityTokenServiceClient(basicCredential))
            {
                var amazonRoleWithSamlResponse = amazonSecurityTokenServiceClient.AssumeRoleWithSAML(assumeRoleWithSamlRequest);
                return new SessionAWSCredentials(amazonRoleWithSamlResponse.Credentials.AccessKeyId,
                    amazonRoleWithSamlResponse.Credentials.SecretAccessKey, amazonRoleWithSamlResponse.Credentials.SessionToken);
            }
        }

        /// <summary>
        /// Disposes resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes resources based on the specified disposing parameter value.
        /// </summary>
        /// <param name="disposing">Indicates if the object has already been disposed.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources here.
                    UnImpersonateUser();
                }
                // Dispose unmanaged resources here.
            }
            disposed = true;
        }

        // Class destructor.
        ~AwsSamlUtility()
        {
            Dispose(false);
        }

        #region Helper Methods

        /// <summary>
        /// Impersonate a user with the specified credentials.
        /// </summary>
        /// <param name="userName">The username of the Windows user account.</param>
        /// <param name="password">The password of the Windows user account.</param>
        /// <param name="domain">The domain of the Windows user account.</param>
        private void ImpersonateUser(string userName, string password, string domain)
        {
            const int LOGON32_TYPE_NEW_CREDENTIALS = 9;
            const int LOGON32_PROVIDER_WINNT50 = 3;
            const int SECURITY_IMPERSONATION = 2;

            var returnValue = LogonUser(userName, domain, password, LOGON32_TYPE_NEW_CREDENTIALS,
                LOGON32_PROVIDER_WINNT50, ref tokenHandle);

            if (!returnValue)
            {
                var lastWin32Error = Marshal.GetLastWin32Error();
                throw new Win32Exception(lastWin32Error);
            }

            returnValue = DuplicateToken(tokenHandle, SECURITY_IMPERSONATION, ref dupeTokenHandle);

            if (!returnValue)
            {
                CloseHandle(tokenHandle);
                return;
            }

            var windowsIdentity = new WindowsIdentity(dupeTokenHandle);
            windowsImpersonationContext = windowsIdentity.Impersonate();
        }

        /// <summary>
        /// Unimpersonates the user.
        /// </summary>
        private void UnImpersonateUser()
        {
            windowsImpersonationContext?.Undo();

            if (tokenHandle != IntPtr.Zero)
            {
                CloseHandle(tokenHandle);
            }

            if (dupeTokenHandle != IntPtr.Zero)
            {
                CloseHandle(dupeTokenHandle);
            }
        }

        /// <summary>
        /// Gets the <see cref="HttpWebResponse"/> based on the web request specified by the URI.
        /// </summary>
        /// <param name="uriAddress">The URI address of the web request.</param>
        /// <returns>Returns a <see cref="HttpWebResponse"/> based on the web request specified by the URI.</returns>
        private static HttpWebResponse GetResult(string uriAddress)
        {
            var uri = new Uri(uriAddress);

            var credentialCache = new CredentialCache
            {
                { uri, "NTLM", CredentialCache.DefaultNetworkCredentials }
            };

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(uri);
            httpWebRequest.UserAgent = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)";
            httpWebRequest.KeepAlive = true;
            httpWebRequest.Credentials = credentialCache;
            httpWebRequest.PreAuthenticate = true;
            httpWebRequest.AllowAutoRedirect = true;
            httpWebRequest.CookieContainer = new CookieContainer();

            var httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();

            return httpWebResponse;
        }

        #endregion

        #region DLL Imports

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string lpszUserName, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool DuplicateToken(IntPtr existingTokenHandle, int securityImpersonationLevel, ref IntPtr duplicateTokenHandle);

        #endregion
    }
}
