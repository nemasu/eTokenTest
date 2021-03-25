///////////////////////////////////////////////////////////////////////////////
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
///////////////////////////////////////////////////////////////////////////////
//
//  Sample to demonstrate how to create a simple certificate request
//  using CertEnroll classes.
//
//  NOTE: This sample requires Visual Studio 2005. Create a project and
//  in the menu click on Project -> Add Reference...
//  this will pop a dialog. Click on the COM tab
//  Select 'CertEnroll 1.0 Type Library' and click OK.
//
//  This will create an interop library which will be used by the C# code.
//
///////////////////////////////////////////////////////////////////////////////

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
