/**
 * Server example with encryption (Basic256Sha256 Sign & Encrypt).
 *
 * This example demonstrates:
 * - Security Policy: Basic256Sha256
 * - Authentication: X.509 Certificate-based
 * - SecurityMode: SignAndEncrypt
 *
 * The server generates self-signed certificates on startup and accepts connections from clients
 * that present trusted certificates. In production, you would load pre-generated certificates
 * from disk and configure a proper PKI.
 *
 * @note Requires open62541 built with encryption (UA_ENABLE_ENCRYPTION) and certificate
 *       generation support (open62541 >= v1.3 with OpenSSL/LibreSSL).
 */

#include <iostream>

#include <open62541pp/config.hpp>

#if defined(UA_ENABLE_ENCRYPTION) && UAPP_HAS_CREATE_CERTIFICATE

#include <open62541pp/node.hpp>
#include <open62541pp/plugin/create_certificate.hpp>
#include <open62541pp/server.hpp>

int main() {
    const std::string serverApplicationUri = "urn:open62541pp.server.application";

    std::cout << "Generating server certificate..." << std::endl;

    // Create self-signed server certificate
    // In production, load certificates from files instead
    const auto serverCert = opcua::createCertificate(
        // Subject (identity of the certificate owner)
        {
            opcua::String{"C=DE"},
            opcua::String{"O=open62541pp"},
            opcua::String{"CN=open62541ppServer@localhost"},
        },
        // Subject Alternative Name (additional identity information)
        {
            opcua::String{"DNS:localhost"},
            opcua::String{std::string{"URI:"} + serverApplicationUri},
        }
    );

    std::cout << "Server certificate generated successfully." << std::endl;

    // Create client certificate (for demonstration purposes, we create it here)
    // In production, client certificates would be pre-generated and added to the trust list
    const auto clientCert = opcua::createCertificate(
        {
            opcua::String{"C=DE"},
            opcua::String{"O=open62541pp"},
            opcua::String{"CN=open62541ppClient@localhost"},
        },
        {
            opcua::String{"DNS:localhost"},
            opcua::String{"URI:urn:open62541pp.client.application"},
        }
    );

    std::cout << "Client certificate generated for trust list." << std::endl;

    // Create server config with encryption enabled
    // Security policies enabled: None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep
    // The server will negotiate the highest security level supported by the client
    opcua::ServerConfig config{
        4840,                      // Port
        serverCert.certificate,    // Server certificate (DER)
        serverCert.privateKey,     // Server private key (PEM)
        {clientCert.certificate},  // Trust list - trusted client certificates (DER)
        {},                        // Issuer list - CA certificates (DER)
        {}                         // Revocation list - CRLs (DER)
    };

    config.setApplicationUri(serverApplicationUri);
    config.setApplicationName("open62541pp Secure Server Example");

    opcua::Server server{std::move(config)};

    // Add a sample variable node that clients can read/write
    opcua::Node{server, opcua::ObjectId::ObjectsFolder}.addVariable(
        {1, 1000},
        "SecureVariable",
        opcua::VariableAttributes{}
            .setAccessLevel(opcua::AccessLevel::CurrentRead | opcua::AccessLevel::CurrentWrite)
            .setDataType(opcua::DataTypeId::Int32)
            .setValueRank(opcua::ValueRank::Scalar)
            .setValue(opcua::Variant{42})
    );

    std::cout << "Secure OPC UA Server started at opc.tcp://localhost:4840" << std::endl;
    std::cout << "Supported security policies:" << std::endl;
    std::cout << "  - None" << std::endl;
    std::cout << "  - Basic128Rsa15" << std::endl;
    std::cout << "  - Basic256" << std::endl;
    std::cout << "  - Basic256Sha256" << std::endl;
    std::cout << "  - Aes128_Sha256_RsaOaep" << std::endl;
    std::cout << std::endl;
    std::cout << "Server is ready to accept encrypted connections." << std::endl;
    std::cout << "Press Ctrl+C to stop the server." << std::endl;

    server.run();
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
