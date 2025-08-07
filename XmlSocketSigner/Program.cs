using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.IO;
using System.Threading.Tasks;
using System.Net.NetworkInformation;

class Program
{
    static async Task Main(string[] args)
    {
        int port = 60000; // default

        // Step 1: Parse port from args if provided
        if (args.Length > 0 && int.TryParse(args[0], out int parsedPort))
        {
            if (parsedPort < 5000 || parsedPort > 90000 || !IsPortAvailable(parsedPort))
            {
                Console.WriteLine("❌ Port not available or out of range (5000-90000).");
                return;
            }
            port = parsedPort;
        }

        string prefix = $"http://localhost:{port}/signxml/";

        HttpListener listener = new HttpListener();
        listener.Prefixes.Add(prefix);

        try
        {
            listener.Start();
            Console.WriteLine($"✅ Listening at {prefix}");
        }
        catch (HttpListenerException ex)
        {
            Console.WriteLine($"❌ Failed to bind to port {port}: {ex.Message}");
            return;
        }

        while (true)
        {
            var context = await listener.GetContextAsync();
            if (context.Request.HttpMethod != "POST")
            {
                await WriteErrorResponse(context.Response, "Method Not Allowed", 405);
                continue;
            }

            using var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding);
            string xmlInput = await reader.ReadToEndAsync();

            if (string.IsNullOrWhiteSpace(xmlInput))
            {
                await WriteErrorResponse(context.Response, "Invalid XML: Input is empty", 400);
                continue;
            }

            try
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.LoadXml(xmlInput);

                X509Certificate2 cert = SelectCertificate();
                if (cert == null)
                {
                    await WriteErrorResponse(context.Response, "No certificate selected", 400);
                    continue;
                }

                SignXml(xmlDoc, cert);

                context.Response.StatusCode = 200;
                context.Response.ContentType = "text/xml";

                byte[] buffer = Encoding.UTF8.GetBytes(xmlDoc.OuterXml);
                await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                context.Response.Close();
            }
            catch (XmlException xe)
            {
                await WriteErrorResponse(context.Response, $"Invalid XML format: {xe.Message}", 400);
            }
            catch (Exception ex)
            {
                await WriteErrorResponse(context.Response, $"Internal server error: {ex.Message}", 500);
            }
        }
    }

    static bool IsPortAvailable(int port)
    {
        IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
        var listeners = ipGlobalProperties.GetActiveTcpListeners();
        return listeners.All(p => p.Port != port);
    }

    static async Task WriteErrorResponse(HttpListenerResponse response, string message, int statusCode)
    {
        response.StatusCode = statusCode;
        response.ContentType = "application/json";

        string json = $@"{{
  ""success"": false,
  ""message"": ""{EscapeJson(message)}"",
  ""statusCode"": {statusCode}
}}";

        byte[] buffer = Encoding.UTF8.GetBytes(json);
        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        response.Close();
    }

    static string EscapeJson(string input) =>
        input.Replace("\\", "\\\\")
             .Replace("\"", "\\\"")
             .Replace("\n", "\\n")
             .Replace("\r", "\\r");

    static X509Certificate2 SelectCertificate()
    {
        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        X509Certificate2Collection collection = X509Certificate2UI.SelectFromCollection(
            store.Certificates,
            "Select Certificate",
            "Select a certificate for signing the XML",
            X509SelectionFlag.SingleSelection);

        store.Close();
        return collection.Count > 0 ? collection[0] : null;
    }

    static void SignXml(XmlDocument xmlDoc, X509Certificate2 cert)
    {
        if (xmlDoc.DocumentElement == null)
            throw new Exception("XML Document is missing a root element.");

        SignedXml signedXml = new SignedXml(xmlDoc)
        {
            SigningKey = cert.GetRSAPrivateKey()
        };

        Reference reference = new Reference { Uri = "" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

        signedXml.AddReference(reference);

        KeyInfo keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();
        XmlElement xmlDigitalSignature = signedXml.GetXml();

        xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
    }
}
