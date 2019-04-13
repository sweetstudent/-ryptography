using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using System.Security.Cryptography;
using System.Security.Permissions;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using Path = System.IO.Path;
using CERTENROLLLib;

namespace WpfApp1
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>

    public partial class MainWindow : Window
    {
        internal static byte[] ReadeFile(string fileName)
        {
            FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }
        public MainWindow()
        {
            InitializeComponent();
        }

        public void Parse()
        {
            try
            {

                

                OpenFileDialog openFileDialog = new OpenFileDialog();
                if (openFileDialog.ShowDialog() == true)
                    namef.Content = Path.GetFileName(openFileDialog.FileName);
                string path = Path.GetFullPath(openFileDialog.FileName);

                X509Certificate2 x509 = new X509Certificate2();
                //Create X509Certificate2 object from .cer file.
                byte[] rawData = ReadeFile(path);
                
                x509.Import(rawData);

                t1.Text = x509.Subject;
                t2.Text = x509.Issuer;
                t3.Text = x509.Version.ToString();
                t4.Text = x509.NotBefore.ToString();
                t5.Text = x509.NotAfter.ToString();
                t6.Text = x509.Thumbprint;
                t7.Text = x509.SerialNumber;
                t8.Text = x509.PublicKey.EncodedKeyValue.Format(true);
                t9.Text = x509.RawData.Length.ToString();
                t10.Text = x509.ToString(true);


                //Add the certificate to a X509Store.
                X509Store store = new X509Store();
                store.Open(OpenFlags.MaxAllowed);
                store.Add(x509);
                store.Close();
            }

            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("Error: The directory specified could not be found.");
            }
            catch (IOException)
            {
                Console.WriteLine("Error: A file in the directory could not be accessed.");
            }
            catch (NullReferenceException)
            {
                Console.WriteLine("File must be a .cer file. Program does not have access to that type of file.");
            }

        }
       

        public static X509Certificate2 CreateSelfSignedCertificate(string subjectName, string issureName)
        {

            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode( subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            var bn = new CX500DistinguishedName();
            bn.Encode(issureName, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create a new private key for the certificate
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = 2048;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone, "SHA512");

            // add extended key usage if you want - look at MSDN for a list of possible OIDs
            var oid = new CObjectId();
            oid.InitializeFromValue("1.3.6.1.5.5.7.3.1"); // SSL server
            var oidlist = new CObjectIds();
            oidlist.Add(oid);
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oidlist);

            // Create the self signing request
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, "");
            cert.Subject = dn;
            cert.Issuer = bn; // the issuer and the subject are the same
            cert.NotBefore = DateTime.Now;
            // this cert expires immediately. Change to whatever makes sense for you
            cert.NotAfter = DateTime.Now;
            cert.X509Extensions.Add((CX509Extension)eku); // add the EKU
            cert.HashAlgorithm = hashobj; // Specify the hashing algorithm
            cert.Encode(); // encode the certificate

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the certificate
            enroll.CertificateFriendlyName = subjectName; // Optional: add a friendly name
            string csr = enroll.CreateRequest(); // Output the request in base64
                                                 // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no password
                                                                // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", // no password, this is for internal consumption
                PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty password)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
            );
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Parse();
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            string subject = t1.Text;
            string issure = t2.Text;

            X509Certificate2 cert = CreateSelfSignedCertificate(subject,issure);
            byte[] b = cert.Export(X509ContentType.Cert);
            FileStream file = new FileStream("mycertificate.cer", FileMode.Create);
            file.Write(b, 0, b.Length);
            file.Close();
        }
    }
    
}
