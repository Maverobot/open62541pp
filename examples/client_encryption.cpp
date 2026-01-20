/**
 * Client example with encryption (Basic256Sha256 Sign & Encrypt).
 *
 * This example demonstrates:
 * - Security Policy: Basic256Sha256
 * - Authentication: X.509 Certificate-based
 * - SecurityMode: SignAndEncrypt
 *
 * The client generates its own certificate and loads trusted server certificates from
 * the "pki/trusted_servers" directory. It also copies its certificate to the server's
 * trusted_clients directory for mutual authentication.
 *
 * Directory structure:
 *   pki/
 *     client/
 *       client_cert.der    - Client's certificate (generated)
 *       client_key.pem     - Client's private key (generated)
 *     trusted_servers/
 *       *.der              - Trusted server certificates (loaded)
 *     trusted_clients/
 *       *.der              - Client copies its cert here for server to trust
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

// Helper to write a ByteString to a file
void writeFile(const fs::path& path, const opcua::ByteString& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + path.string());
    }
    const auto* ptr = reinterpret_cast<const char*>(data.data());  // NOLINT
    file.write(ptr, static_cast<std::streamsize>(data.size()));
    if (!file) {
        throw std::runtime_error("Failed to write file: " + path.string());
    }
}

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

// Load all .der certificate files from a directory
std::vector<opcua::ByteString> loadCertificatesFromDirectory(const fs::path& dir) {
    std::vector<opcua::ByteString> certificates;
    if (!fs::exists(dir)) {
        return certificates;
    }
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".der") {
            std::cout << "  Loading trusted certificate: " << entry.path().filename() << std::endl;
            certificates.push_back(readFile(entry.path()));
        }
    }
    return certificates;
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
            << "The client generates its own certificate and loads server certificates\n"
            << "from pki/trusted_servers/. It also copies its cert to pki/trusted_clients/\n"
            << "so the server can trust it.\n"
            << std::flush;
        return 2;
    }

    const std::string serverUrl = (parser.nargs() > 1)
        ? std::string{parser.args()[parser.nargs() - 1]}
        : "opc.tcp://localhost:4840";

    const std::string clientApplicationUri = "urn:open62541pp.client.application";

    // PKI directory structure
    const fs::path pkiDir = "pki";
    const fs::path clientDir = pkiDir / "client";
    const fs::path trustedServersDir = pkiDir / "trusted_servers";
    const fs::path trustedClientsDir = pkiDir / "trusted_clients";  // Server looks here
    const fs::path clientCertPath = clientDir / "client_cert.der";
    const fs::path clientKeyPath = clientDir / "client_key.pem";

    fs::create_directories(clientDir);
    fs::create_directories(trustedServersDir);
    fs::create_directories(trustedClientsDir);

    opcua::ByteString clientCertificate;
    opcua::ByteString clientPrivateKey;

    // Generate or load client certificate
    if (fs::exists(clientCertPath) && fs::exists(clientKeyPath)) {
        std::cout << "Loading existing client certificate..." << std::endl;
        clientCertificate = readFile(clientCertPath);
        clientPrivateKey = readFile(clientKeyPath);
    } else {
        std::cout << "Generating client certificate..." << std::endl;
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
        clientPrivateKey = clientCert.privateKey;

        writeFile(clientCertPath, clientCertificate);
        writeFile(clientKeyPath, clientPrivateKey);
        std::cout << "Client certificate saved to " << clientCertPath << std::endl;
    }

    // Copy client certificate to trusted_clients directory so server can trust it
    const fs::path trustedClientCertPath = trustedClientsDir / "client_cert.der";
    if (!fs::exists(trustedClientCertPath)) {
        writeFile(trustedClientCertPath, clientCertificate);
        std::cout << "Client certificate copied to " << trustedClientCertPath << std::endl;
        std::cout << "(Server will trust this certificate on next restart)" << std::endl;
    }

    // Load trusted server certificates from directory
    std::cout << "Loading trusted server certificates from " << trustedServersDir << "..." << std::endl;
    auto trustedServerCerts = loadCertificatesFromDirectory(trustedServersDir);

    // Also check for server cert in server directory (for convenience)
    const fs::path serverCertPath = pkiDir / "server" / "server_cert.der";
    if (trustedServerCerts.empty() && fs::exists(serverCertPath)) {
        std::cout << "  Loading server certificate from " << serverCertPath << std::endl;
        trustedServerCerts.push_back(readFile(serverCertPath));
        // Copy to trusted_servers for future runs
        fs::copy_file(serverCertPath, trustedServersDir / "server_cert.der", 
                      fs::copy_options::skip_existing);
    }

    if (trustedServerCerts.empty()) {
        std::cerr << "No trusted server certificates found." << std::endl;
        std::cerr << "Please run server_encryption first, then copy pki/server/server_cert.der" << std::endl;
        std::cerr << "to pki/trusted_servers/ directory." << std::endl;
        return 1;
    }

    // Create client config with encryption enabled
    opcua::ClientConfig config{
        clientCertificate,    // Client certificate (DER)
        clientPrivateKey,     // Client private key (PEM)
        trustedServerCerts,   // Trust list - trusted server certificates (DER)
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
        std::cerr << "Make sure the server is running and trusts this client's certificate." << std::endl;
        std::cerr << "(The server needs to be restarted to load new trusted certificates)" << std::endl;
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
