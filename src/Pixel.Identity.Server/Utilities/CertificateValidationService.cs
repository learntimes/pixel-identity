using System.Security.Cryptography.X509Certificates;


namespace Pixel.Identity.Server.Utilities
{
    public interface ICertificateValidationService
    {
        public bool ValidateCertificate(X509Certificate2 clientCertificate);
    }
    public class CertificateValidationService : ICertificateValidationService
    {
        private readonly IConfiguration configuration;

        public CertificateValidationService(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public bool ValidateCertificate(X509Certificate2 clientCertificate)
        {
            X509Certificate2 expectedCertificate;
            string pfxFilePath = this.configuration.GetValue<string>("Identity:Certificates:SSLCertificatePath");
            string pfxFilePassword = this.configuration.GetValue<string>("Identity:Certificates:SSLCertificateKey");

            // File.Exists(Path.Combine(Directory.GetCurrentDirectory(), pfxFilePath))
            if (File.Exists( pfxFilePath))
            {
                var certificateBytes = File.ReadAllBytes(pfxFilePath);
                expectedCertificate = new X509Certificate2(certificateBytes, pfxFilePassword);
                Console.WriteLine("vThumbprint: "+expectedCertificate.Thumbprint);
                return clientCertificate.Thumbprint == expectedCertificate.Thumbprint;
                
            }
            else
            {
                return clientCertificate.Thumbprint == this.configuration.GetValue<string>("Identity:Certificates:SSLCertificateThumbprint");
            }
        }
    }
}