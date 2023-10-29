#include <iostream>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <io.h>
#include <fstream>
#include <cstring>
#include <string>
#include <thread>
#include <cassert>
#include <limits>
#include <stdexcept>
#include <cctype>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstddef>
#include <vector>
#include <Windows.h>
#include <filesystem>

#pragma comment(lib, "Ws2_32.lib")
using namespace std::experimental::filesystem::v1;


std::string AddListnerToHTML(std::string Context) {
    std::string content = Context;
    size_t pos = Context.find("<body>");
    std::string ListnerCode = "<script>\n"
        "  let initial = true;\n"
        "  let ws = new WebSocket(\"ws://localhost:9000\");\n"
        "  ws.onopen = (event) => {\n"
        "    console.log(\"Connected to Dhananjay server\");\n"
        "  };\n"
        "  ws.onmessage = (event) => {\n"
        "    if (event.data == \"FILE_CHANGE_DETECTED\") {\n"
        "      if (initial) {\n"
        "        initial = false;\n"
        "      } else {\n"
        "        location.reload();\n"
        "      }\n"
        "    }\n"
        "  };\n"
        "</script>";
    if (pos != std::string::npos) {
        content.insert(pos + 6, ListnerCode);
    }
    return content;
}

std::string readContent() {
    std::ifstream HTMLFILE("C:\\html\\index.html");
    if (HTMLFILE.is_open()) {
        std::string fileContent((std::istreambuf_iterator<char>(HTMLFILE)),
            std::istreambuf_iterator<char>());
        HTMLFILE.close();
        return AddListnerToHTML(fileContent);
    }
    return "test";
}

int sendResponse(SOCKET socket) {

    std::string responseCode = "HTTP/1.1 200 OK\r\n"
        "Content-Length: " + std::to_string(readContent().length()) + "\r\n"
        "X-Powered-By: Nemesis\r\n"
        "X-Coded-By: SSsenday\r\n"
        "Content-Type: text/html\r\n"
        "\r\n" + readContent();

    const char* response = responseCode.c_str();
    int bytesSent = send(socket, response, strlen(response), 0);
    if (bytesSent == SOCKET_ERROR) {
        std::cout << "Failed to send response. Error code: " << WSAGetLastError() << std::endl;
    }
    return bytesSent;

}

void handleClient(SOCKET socket) {
    if (socket == INVALID_SOCKET) {
        std::cout << "Failed to accept connection. Error code: " << WSAGetLastError() << std::endl;
        return;
    }

    if (sendResponse(socket) == SOCKET_ERROR) {
        std::cout << "Failed to send response to client." << std::endl;
    }

    //closesocket(socket);
}

bool isWebSocketConnection(char* RespHead, int Size) {
    ;
    std::string RespHeader(RespHead, Size);

    if (RespHeader.find("Sec-WebSocket-Key:")) {
        return true;
    }
    return false;
}


std::string extractWebSocketKey(const char* buffer) {
    std::string keyHeader = "Sec-WebSocket-Key: ";
    //std::cout << buffer;
    const char* keyStart = strstr(buffer, keyHeader.c_str());

    if (keyStart) {
        keyStart += keyHeader.length();
        const char* keyEnd = strchr(keyStart, '\r');

        if (keyEnd) {
            std::string key(keyStart, keyEnd);
            return key;
        }
    }

    return "";
}


void SendWebSocketSwitch(SOCKET acceptors, std::string ACCEPT_KEY) {
    std::string RESPONSE_HEADER = "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket \r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + ACCEPT_KEY + "\r\n\r\n";

    const char* Bufff = RESPONSE_HEADER.c_str();
    //std::cout << RESPONSE_HEADER;
    int bytesSent = send(acceptors, Bufff, strlen(Bufff), 0);
    if (bytesSent == SOCKET_ERROR) {
        std::cout << "Failed to send response. Error code: " << WSAGetLastError() << std::endl;
    }
}





std::string base6411_encode(const unsigned char* input, int length) {
    BIO* bmem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string output(bptr->data, bptr->length - 1);

    BIO_free_all(b64);

    return output;
}

std::string generateWebSocketAccept(const std::string& webSocketKey) {
    std::string guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string concatenated = webSocketKey + guid;

    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(concatenated.c_str()), concatenated.length(), digest);

    return base6411_encode(digest, SHA_DIGEST_LENGTH);
}


std::string decodeWebSocketMessage(const std::string& message) {
    //std::cout << message;
    std::string decodedMessage;

    // Skip the first two bytes (WebSocket frame header)
    size_t offset = 2;
    size_t length = message.length();

    while (offset < length) {
        unsigned char byte = static_cast<unsigned char>(message[offset++]);

        if (byte == 0xFF) {
            // End of the message
            break;
        }

        decodedMessage += byte;
    }

    return decodedMessage;
}



void ReadWSSMessage(SOCKET socket) {
    // https://www.rfc-editor.org/rfc/rfc6455#section-5.2

    unsigned char buffer[4096];
    int bytesRead;

    while ((bytesRead = recv(socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0)) > 0) {
        // WebSocket frame decoding
        int index = 0;

        //std::cout << static_cast<int> (buffer[0]);
        // Assuming a single WebSocket frame in each recv call
        unsigned char firstByte = buffer[index++];
        unsigned char secondByte = buffer[index++];

        bool fin = (firstByte & 0x80) != 0;  // Check the FIN bit
        int opcode = firstByte & 0x0F;       // Extract the opcode

        bool masked = (secondByte & 0x80) != 0;  // Check the MASK bit
        int payloadLength = secondByte & 0x7F;    // Extract the payload length

        // Decoding the payload length
        if (payloadLength == 126) {
            // If the payload length is 126, the actual length is stored in the following 2 bytes
            payloadLength = (buffer[index++] << 8) | buffer[index++];
        }
        else if (payloadLength == 127) {
            // If the payload length is 127, the actual length is stored in the following 8 bytes
            // Note: This implementation assumes the payload length does not exceed 2^32-1
            index += 4; // Skip the additional 4 bytes (not handling payload length > 2^32-1)
            payloadLength = (buffer[index++] << 24) | (buffer[index++] << 16) |
                (buffer[index++] << 8) | buffer[index++];
        }

        // Decoding the masking key (if masked)
        std::vector<unsigned char> maskingKey;
        if (masked) {
            maskingKey.push_back(buffer[index++]);
            maskingKey.push_back(buffer[index++]);
            maskingKey.push_back(buffer[index++]);
            maskingKey.push_back(buffer[index++]);
        }

        // Decoding the payload data
        std::vector<unsigned char> payloadData;
        for (int i = 0; i < payloadLength; ++i) {
            unsigned char decodedByte = buffer[index++];
            if (masked) {
                decodedByte ^= maskingKey[i % 4];  // Apply the masking key
            }
            payloadData.push_back(decodedByte);
        }

        // Print the decoded payload data
       // for (const auto& byte : payloadData) {
         //   std::cout << byte;
        //}

        // Check if this is the last frame
        if (fin) {
            break;
        }
    }
}
void SendWSSMessage(SOCKET socket, const std::string& message) {
    // Prepare the WebSocket frame header
    unsigned char header[10];
    header[0] = 0x81;  // FIN bit set (1), opcode for text message (0x1)

    // Calculate the payload length
    size_t messageLength = message.length();
    if (messageLength <= 125) {
        header[1] = static_cast<unsigned char>(messageLength);
    }
    else if (messageLength <= 65535) {
        header[1] = 126;
        header[2] = static_cast<unsigned char>((messageLength >> 8) & 0xFF);
        header[3] = static_cast<unsigned char>(messageLength & 0xFF);
    }
    else {
        std::cout << "Message length exceeds the supported limit." << std::endl;
        return;
    }

    // Send the WebSocket frame header
    int bytesSent = send(socket, reinterpret_cast<const char*>(header), (header[1] <= 125 ? 2 : 4), 0);
    if (bytesSent == SOCKET_ERROR) {
        std::cout << "Failed to send WebSocket frame header." << std::endl;
        return;
    }

    // Send the message payload
    bytesSent = send(socket, message.c_str(), messageLength, 0);
    if (bytesSent == SOCKET_ERROR) {
        std::cout << "Failed to send WebSocket message payload." << std::endl;
        return;
    }

    //std::cout << "WebSocket message sent successfully." << std::endl;
}



bool isFileModified(const std::string& filePath, std::filesystem::file_time_type& lastModified)
{
    std::filesystem::file_time_type currentModified = std::filesystem::last_write_time(filePath);
    if (currentModified > lastModified)
    {
        lastModified = currentModified;
        return true;
    }
    return false;
}


void LookForFileChange(std::string filePath, SOCKET socket) {
    std::filesystem::file_time_type lastModified = (std::filesystem::file_time_type::min)();
    ;    while (true)
    {
        if (isFileModified(filePath, lastModified))
        {
           // std::cout << "File has been modified!" << std::endl;
            // Perform actions on file change

            SendWSSMessage(socket, "FILE_CHANGE_DETECTED");
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void RequestInitlizer(SOCKET Accesptor) {
    char Buffer[1024];
    std::string request;
    int bytesRead;
    do {
        bytesRead = recv(Accesptor, Buffer, sizeof(Buffer), 0);
        if (bytesRead > 0) {
            request.append(Buffer, bytesRead);
            //  std::cout << Buffer;

            if (request.find("Sec-WebSocket-Key: ") != std::string::npos &&
                request.find("Sec-WebSocket-Version:") != std::string::npos) {
                if (isWebSocketConnection(Buffer, sizeof(Buffer))) {
                    char TempBuff[1024];

                    auto key = extractWebSocketKey(Buffer);
                    //std::cout << "Recived Key" << key << std::endl << std::endl;
                    // std::string salt = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                    SendWebSocketSwitch(Accesptor, generateWebSocketAccept(key));
                    // ReadWSSMessage(Accesptor);

                    std::string filePath = "C:\\html\\index.html";
                    std::thread t1(LookForFileChange, filePath, Accesptor);
                    t1.detach();
                    //SendWSSMessage(Accesptor, "HELLO DHANANANJAY");
                }
                break;
            }
            else {
              //  std::cout << "HELLO";
                sendResponse(Accesptor);
            }

            // Clear the request string for the next iteration
            request.clear();
        }
    } while (bytesRead > 0);
}



int main() {


    std::cout << "Server Listening on Port 9000";

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "Failed to initialize Winsock";
        return 1;
    }

    SOCKET SocketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (SocketDescriptor == INVALID_SOCKET) {
        std::cout << "Failed to create socket";
        WSACleanup();
        return 1;
    }

    struct sockaddr_in ADDRESS;
    ADDRESS.sin_family = AF_INET;
    ADDRESS.sin_port = htons(9000);
    ADDRESS.sin_addr.S_un.S_addr = INADDR_ANY;

    if (bind(SocketDescriptor, (struct sockaddr*)&ADDRESS, sizeof(ADDRESS)) == SOCKET_ERROR) {
        std::cout << "Failed to bind socket";
        closesocket(SocketDescriptor);
        WSACleanup();
        return 1;
    }

    if (listen(SocketDescriptor, 1000) == SOCKET_ERROR) {
        std::cout << "Failed to listen on socket";
        closesocket(SocketDescriptor);
        WSACleanup();
        return 1;
    }

    while (true) {
        SOCKET Accesptor = accept(SocketDescriptor, NULL, NULL);
        std::thread t1(RequestInitlizer, Accesptor);
        t1.detach();
    }

    closesocket(SocketDescriptor);
    WSACleanup();


    return 0;
}
