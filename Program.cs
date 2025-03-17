using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main()
    {
        var cert = GenerateSelfSignedCertificate("CN=OPCClient");
        File.WriteAllBytes("certificate.pfx", cert.Export(X509ContentType.Pfx));
        Console.WriteLine("Zertifikat erstellt: certificate.pfx");
    }

    static X509Certificate2 GenerateSelfSignedCertificate(string subjectName)
    {
        using (var rsa = RSA.Create(2048))
        {
            var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

            var cert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }
    }
}
