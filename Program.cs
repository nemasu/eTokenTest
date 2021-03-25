using System;


//  Add the CertEnroll namespace
using CERTENROLLLib;

namespace CreateSimpleCertRequest
{
    class CreateSimpleCertRequest
    {
        static void Main()
        {
            CX509Enrollment enroll = new CX509Enrollment();
            CX509PrivateKey pri = new CX509PrivateKey();
            CX509CertificateRequestPkcs10 request = new CX509CertificateRequestPkcs10();
            CX500DistinguishedName dn = new CX500DistinguishedName();

            pri.ProviderName = "eToken Base Cryptographic Provider";
            pri.Length = 2048;
            pri.KeySpec = X509KeySpec.XCN_AT_KEYEXCHANGE;
            
            //pri.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_DECRYPT_FLAG;

            pri.ProviderType = X509ProviderType.XCN_PROV_RSA_FULL;
            pri.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_NONE;

            request.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextUser,pri,"");
            dn.Encode("CN=KimiNoNaWa", X500NameFlags.XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG);
            request.Subject = dn;

            enroll.InitializeFromRequest(request);
            string pkcs10 = enroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            Console.WriteLine(pkcs10);

            //Do Enrollment
            
            //Install certificate
            //enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedRoot, pkcs10, EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER, "");
        }
    }
}
