/**
 * Server example with encryption (Basic256Sha256 Sign & Encrypt).
 *
 * This example demonstrates:
 * - Security Policy: Basic256Sha256
 * - Authentication: X.509 Certificate-based
 * - SecurityMode: SignAndEncrypt
 *
 * The server generates certificates and saves them to files in a "pki" directory.
 * The client_encryption example loads these certificates to establish a secure connection.
 * External clients (UaExpert, python-opcua) can also use these certificates.
 *
 * @note Requires open62541 built with encryption (UA_ENABLE_ENCRYPTION) and certificate
 *       generation support (open62541 >= v1.3 with OpenSSL/LibreSSL).
 */

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include <open62541pp/config.hpp>

#if defined(UA_ENABLE_ENCRYPTION) && UAPP_HAS_CREATE_CERTIFICATE

#include <open62541pp/node.hpp>
#include <open62541pp/plugin/create_certificate.hpp>
#include <open62541pp/server.hpp>

namespace fs = std::filesystem;

// Helper to write a ByteString to a file
void writeFile(const fs::path& path, const opcua::ByteString& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to write file: " + path.string());
    }
    const auto* ptr = reinterpret_cast<const char*>(data.data());  // NOLINT
    file.write(ptr, static_cast<std::streamsize>(data.size()));
}

// Helper to read a ByteString from a file
opcua::ByteString readFile(const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to read file: " + path.string());
    }
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(buffer.data()), size);  // NOLINT
    return opcua::ByteString{buffer.begin(), buffer.end()};
}

int main() {
    const std::string serverApplicationUri = "urn:open62541pp.server.application";
    const std::string clientApplicationUri = "urn:open62541pp.client.application";

    // Create PKI directory structure
    const fs::path pkiDir = "pki";
    const fs::path serverCertPath = pkiDir / "server_cert.der";
    const fs::path serverKeyPath = pkiDir / "server_key.pem";
    const fs::path clientCertPath = pkiDir / "client_cert.der";
    const fs::path clientKeyPath = pkiDir / "client_key.pem";

    fs::create_directories(pkiDir);

    opcua::ByteString serverCertificate;
    opcua::ByteString serverPrivateKey;
    opcua::ByteString clientCertificate;

    // Check if certificates already exist, otherwise generate them
    if (fs::exists(serverCertPath) && fs::exists(serverKeyPath)) {
        std::cout << "Loading existing server certificate from " << pkiDir << "..." << std::endl;
        serverCertificate = readFile(serverCertPath);
        serverPrivateKey = readFile(serverKeyPath);
    } else {
        std::cout << "Generating server certificate..." << std::endl;
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
        serverCertificate = serverCert.certificate;
        serverPrivateKey = serverCert.privateKey;

        writeFile(serverCertPath, serverCertificate);
        writeFile(serverKeyPath, serverPrivateKey);
        std::cout << "Server certificate saved to " << serverCertPath << std::endl;
    }

    // Generate client certificate for trust list (shared with client_encryption example)
    if (fs::exists(clientCertPath)) {
        std::cout << "Loading existing client certificate from " << clientCertPath << "..." << std::endl;
        clientCertificate = readFile(clientCertPath);
    } else {
        std::cout << "Generating client certificate for trust list..." << std::endl;
        const auto clientCert = opcua::createCertificate(
            {
                opcua::String{"C=DE"},
                opcua::String{"O=open62541pp"},
                opcua::String{"CN=open62541ppClient@localhost"},
            },
            {
                opcua::String{"DNS:localhost"},
                opcua::String{std::string{"URI:"} + clientApplicationUri},
            }
        );
        clientCertificate = clientCert.certificate;

        writeFile(clientCertPath, clientCert.certificate);
        writeFile(clientKeyPath, clientCert.privateKey);
        std::cout << "Client certificate saved to " << clientCertPath << std::endl;
    }

    // Create server config with encryption enabled
    // Security policies enabled: None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep
    opcua::ServerConfig config{
        4840,               // Port
        serverCertificate,  // Server certificate (DER)
        serverPrivateKey,   // Server private key (PEM)
        {clientCertificate},  // Trust list - trusted client certificates (DER)
        {},                 // Issuer list - CA certificates (DER)
        {}                  // Revocation list - CRLs (DER)
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

    std::cout << std::endl;
    std::cout << "Secure OPC UA Server started at opc.tcp://localhost:4840" << std::endl;
    std::cout << "Supported security policies:" << std::endl;
    std::cout << "  - None" << std::endl;
    std::cout << "  - Basic128Rsa15" << std::endl;
    std::cout << "  - Basic256" << std::endl;
    std::cout << "  - Basic256Sha256" << std::endl;
    std::cout << "  - Aes128_Sha256_RsaOaep" << std::endl;
    std::cout << std::endl;
    std::cout << "Certificates are stored in: " << fs::absolute(pkiDir) << std::endl;
    std::cout << "  - Server certificate: " << serverCertPath << std::endl;
    std::cout << "  - Client certificate: " << clientCertPath << " (for client_encryption example)" << std::endl;
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
