/**
 * Client example with encryption (Basic256Sha256 Sign & Encrypt).
 *
 * This example demonstrates:
 * - Security Policy: Basic256Sha256
 * - Authentication: X.509 Certificate-based
 * - SecurityMode: SignAndEncrypt
 *
 * The client generates a self-signed certificate on startup and connects to a secure server.
 * In production, you would load pre-generated certificates from disk and configure a proper PKI.
 *
 * @note Requires open62541 built with encryption (UA_ENABLE_ENCRYPTION) and certificate
 *       generation support (open62541 >= v1.3 with OpenSSL/LibreSSL).
 */

#include <iostream>

#include <open62541pp/config.hpp>

#if defined(UA_ENABLE_ENCRYPTION) && UAPP_HAS_CREATE_CERTIFICATE

#include <open62541pp/client.hpp>
#include <open62541pp/node.hpp>
#include <open62541pp/plugin/create_certificate.hpp>

#include "helper.hpp"  // CliParser

int main(int argc, char* argv[]) {
    const CliParser parser{argc, argv};
    if (parser.hasFlag("-h") || parser.hasFlag("--help")) {
        std::cout
            << "usage: client_encryption [options] [opc.tcp://<host>:<port>]\n"
            << "options:\n"
            << "  --help, -h\n"
            << "\n"
            << "This example demonstrates X.509 certificate-based authentication\n"
            << "with SignAndEncrypt security mode (Basic256Sha256 policy).\n"
            << std::flush;
        return 2;
    }

    const std::string serverUrl = (parser.nargs() > 1)
        ? std::string{parser.args()[parser.nargs() - 1]}
        : "opc.tcp://localhost:4840";

    const std::string serverApplicationUri = "urn:open62541pp.server.application";
    const std::string clientApplicationUri = "urn:open62541pp.client.application";

    std::cout << "Generating client certificate..." << std::endl;

    // Create self-signed client certificate
    // In production, load certificates from files instead
    const auto clientCert = opcua::createCertificate(
        // Subject (identity of the certificate owner)
        {
            opcua::String{"C=DE"},
            opcua::String{"O=open62541pp"},
            opcua::String{"CN=open62541ppClient@localhost"},
        },
        // Subject Alternative Name (additional identity information)
        {
            opcua::String{"DNS:localhost"},
            opcua::String{std::string{"URI:"} + clientApplicationUri},
        }
    );

    std::cout << "Client certificate generated successfully." << std::endl;

    // Create server certificate (for demonstration purposes)
    // In production, this would be the actual server's certificate from a trusted source
    const auto serverCert = opcua::createCertificate(
        {
            opcua::String{"C=DE"},
            opcua::String{"O=open62541pp"},
            opcua::String{"CN=open62541ppServer@localhost"},
        },
        {
            opcua::String{"DNS:localhost"},
            opcua::String{std::string{"URI:"} + serverApplicationUri},
        }
    );

    std::cout << "Server certificate added to trust list." << std::endl;

    // Create client config with encryption enabled
    opcua::ClientConfig config{
        clientCert.certificate,    // Client certificate (DER)
        clientCert.privateKey,     // Client private key (PEM)
        {serverCert.certificate},  // Trust list - trusted server certificates (DER)
        {}                         // Revocation list - CRLs (DER)
    };

    // Set security mode to SignAndEncrypt (highest security)
    // This will use the Basic256Sha256 security policy (or higher if available)
    config.setSecurityMode(opcua::MessageSecurityMode::SignAndEncrypt);

    // Set client application URI (should match the certificate's SubjectAltName URI)
    opcua::asWrapper<opcua::String>(config->clientDescription.applicationUri) =
        opcua::String{clientApplicationUri};

    // Use X.509 certificate for user authentication
    // The certificate is used both for the secure channel and user authentication
    config.setUserIdentityToken(opcua::X509IdentityToken{clientCert.certificate});

    opcua::Client client{std::move(config)};

    std::cout << "Connecting to " << serverUrl << " with SignAndEncrypt mode..." << std::endl;

    try {
        client.connect(serverUrl);
        std::cout << "Connected successfully using encrypted channel!" << std::endl;

        // Read the server's current time as a simple test
        opcua::Node timeNode{client, opcua::VariableId::Server_ServerStatus_CurrentTime};
        const auto serverTime = timeNode.readValue().to<opcua::DateTime>();
        std::cout << "Server time (UTC): " << serverTime.format("%Y-%m-%d %H:%M:%S") << std::endl;

        // Try to read the secure variable if it exists (from server_encryption example)
        try {
            opcua::Node secureVarNode{client, opcua::NodeId{1, 1000}};
            const auto value = secureVarNode.readValue().to<int32_t>();
            std::cout << "SecureVariable value: " << value << std::endl;
        } catch (const opcua::BadStatus&) {
            // Node might not exist if connecting to a different server
        }

        client.disconnect();
        std::cout << "Disconnected from server." << std::endl;

    } catch (const opcua::BadStatus& e) {
        std::cerr << "Connection failed: " << e.what() << std::endl;
        std::cerr
            << "\nNote: Make sure the server's certificate is in the client's trust list,\n"
            << "and the client's certificate is in the server's trust list.\n"
            << "Run 'server_encryption' example first to start a compatible secure server.\n"
            << std::endl;
        return 1;
    }

    return 0;
}

#else

int main() {
    std::cerr
        << "This example requires encryption support.\n"
        << "Please rebuild open62541 and open62541pp with encryption enabled:\n"
        << "  - UA_ENABLE_ENCRYPTION=ON\n"
        << "  - open62541 >= v1.3 with OpenSSL/LibreSSL\n"
        << std::endl;
    return 1;
}

#endif
