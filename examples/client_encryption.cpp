/**
 * Client example with encryption (Basic256Sha256 Sign & Encrypt).
 *
 * This example demonstrates:
 * - Security Policy: Basic256Sha256
 * - Authentication: X.509 Certificate-based
 * - SecurityMode: SignAndEncrypt
 *
 * The client loads certificates from the "pki" directory created by server_encryption.
 * Run server_encryption first to generate the certificates.
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

#include <open62541pp/client.hpp>
#include <open62541pp/node.hpp>
#include <open62541pp/plugin/create_certificate.hpp>

#include "helper.hpp"  // CliParser

namespace fs = std::filesystem;

// Helper to read a ByteString from a file
opcua::ByteString readFile(const fs::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading: " + path.string());
    }
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(buffer.data()), size);  // NOLINT
    if (!file) {
        throw std::runtime_error("Failed to read file: " + path.string());
    }
    return opcua::ByteString{buffer.begin(), buffer.end()};
}

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
            << "\n"
            << "Run server_encryption first to generate the certificates in the 'pki' directory.\n"
            << std::flush;
        return 2;
    }

    const std::string serverUrl = (parser.nargs() > 1)
        ? std::string{parser.args()[parser.nargs() - 1]}
        : "opc.tcp://localhost:4840";

    const std::string clientApplicationUri = "urn:open62541pp.client.application";

    // PKI directory paths (shared with server_encryption example)
    const fs::path pkiDir = "pki";
    const fs::path serverCertPath = pkiDir / "server_cert.der";
    const fs::path clientCertPath = pkiDir / "client_cert.der";
    const fs::path clientKeyPath = pkiDir / "client_key.pem";

    // Check if certificates exist
    if (!fs::exists(clientCertPath) || !fs::exists(clientKeyPath) || !fs::exists(serverCertPath)) {
        std::cerr
            << "Certificate files not found in '" << fs::absolute(pkiDir) << "'.\n"
            << "Please run server_encryption first to generate the certificates.\n"
            << std::endl;
        return 1;
    }

    std::cout << "Loading certificates from " << fs::absolute(pkiDir) << "..." << std::endl;

    // Load certificates from files
    const auto clientCertificate = readFile(clientCertPath);
    const auto clientPrivateKey = readFile(clientKeyPath);
    const auto serverCertificate = readFile(serverCertPath);

    std::cout << "Certificates loaded successfully." << std::endl;

    // Create client config with encryption enabled
    opcua::ClientConfig config{
        clientCertificate,    // Client certificate (DER)
        clientPrivateKey,     // Client private key (PEM)
        {serverCertificate},  // Trust list - trusted server certificates (DER)
        {}                    // Revocation list - CRLs (DER)
    };

    // Set security mode to SignAndEncrypt (highest security)
    config.setSecurityMode(opcua::MessageSecurityMode::SignAndEncrypt);

    // Set client application URI (should match the certificate's SubjectAltName URI)
    opcua::asWrapper<opcua::String>(config->clientDescription.applicationUri) =
        opcua::String{clientApplicationUri};

    // Note: We use anonymous user authentication over the encrypted channel.
    // The encryption is handled at the transport layer using the certificates.
    // For X.509 user authentication (which is different from transport encryption),
    // additional server-side access control configuration would be required.

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
