#include <unordered_map>
#include <array>
#include <thread>

#include <SFML/Network.hpp>


// A utility function for making a socket bind in a non blocking way
bool NonBlockingSocket(sf::UdpSocket& socket, const sf::IpAddress ip, const unsigned short port) {
    if (sf::Socket::Done == socket.bind(port, ip)) {
        socket.setBlocking(false);
        return true;
    } else {
        return false;
    }
}

template<typename MessageType>
class Networker;

template<typename MessageType>
class PacketHandler {
public:
    using MyNetworker = Networker<MessageType>;

    // Do something with the packet.
    // Return a boolean indicating that everything can continue
    virtual bool Handle(MyNetworker* networker) = 0;
}; 

template<typename MessageType>
class Networker {
public:
    // Recieve packets and dispatch them to the appropriate handler.
    // It's best to use this function like so: for (; networker.Recieve(); );
    // in order to handle all the incoming packets as quickly as possible.
    bool Receive() {
        size_t numBytesReceived = 0;
        const auto status = socket->receive(buffer.data(), sizeof(buffer), numBytesReceived, senderAddress, senderPort);
        if (status != sf::Socket::Done) {
            return false;
        }
        static_assert(sizeof(MessageType) == sizeof(buffer[0]));
        const auto messageType = static_cast<MessageType>(buffer[0]);
        auto handler = FindHandler(messageType);
        if (handler == nullptr) {
            return true;
        } else {
            return handler->Handle(this);
        }
    }


    // Sets the socket which the networker receives from
    void RegisterSocket(sf::UdpSocket* socket) {
        this->socket = socket;
    }

    // Set a handler to process the packet. If the handler pointer is null, then it will be removed.
    void RegisterHandler(const MessageType message, PacketHandler<MessageType>* handler) {
        if (handler != nullptr) {
            handlers[message] = handler;
        } else {
            if (auto iter = handlers.find(message); iter != handlers.end()) {
                handlers.erase(iter);
            }
        }
    }

    template<typename Packet>
    Packet GetPacket() const { return reinterpret_cast<Packet>(buffer.data()); }
    sf::IpAddress GetSenderIpAddress() const { return senderAddress; }
    unsigned short GetSenderPort() const { return senderPort; }

    template<typename Packet>
    bool Send(const Packet packet) {
        return sf::Socket::Done == socket->send(&packet, sizeof(packet), GetSenderIpAddress(), GetSenderPort());
    }

    template<typename Packet>
    bool Send(const Packet packet, const sf::IpAddress ipAddress, const unsigned short port) {
        return sf::Socket::Done == socket->send(&packet, sizeof(packet), ipAddress, port);
    }


private:
    PacketHandler<MessageType>* FindHandler(const MessageType message) {
        if (auto iter = handlers.find(message); iter != handlers.end()) {
            auto& [_, pointer] = *iter;
            return pointer;
        } else {
            return nullptr;
        }
    }

    constexpr static int BufferSize = 4096;
    sf::IpAddress senderAddress;
    unsigned short senderPort;
    sf::UdpSocket* socket;
    std::unordered_map<
        MessageType,
        PacketHandler<MessageType>*
    > handlers;
    std::array<std::uint8_t, BufferSize> buffer;
};

struct User {
    using Id = unsigned long;

    // Make a unique number for that user
    static Id MakeId(const sf::IpAddress ipAddress, const unsigned short port) {
        const auto ipAsInteger = ipAddress.getPublicAddress().toInteger();
        Id id {};
        id |= static_cast<Id>(ipAsInteger);
        id |= static_cast<Id>(port) << sizeof(ipAsInteger);
        return id;
    }

    sf::IpAddress ipAddress;
    unsigned short port;
    // time_t pingTime;
    // Vector3 position;
    // int health;
};

struct ServerState {
    std::unordered_map<User::Id, std::unique_ptr<User>> users;

    bool AddUser(const sf::IpAddress ipAddress, const unsigned short port) {
        const auto id = User::MakeId(ipAddress, port);
        
        if (users.contains(id)) {
            printf("User %zu already exists.\n", id);
            return false;
        }

        auto user = std::make_unique<User>();
        user->ipAddress = ipAddress;
        user->port = port;
        users[id] = std::move(user);
        // Then send a message to the other clients that a new user has joined!
        return true;
    }

    void RemoveUser(const User::Id id) {
        // Simply erase them from the user map
        if (const auto iter = users.find(id); iter != users.end()) {
            users.erase(iter);
        }
    }
};

// Packets sent from the clients
namespace client {
    enum struct MessageType : std::uint8_t {
        JoinRequest,
        Pong
    };

    struct JoinRequestPacket {
        MessageType type = MessageType::JoinRequest;
    };

    struct PongPacket {
        MessageType type = MessageType::Pong;
    };

}

// Packets sent from the server
namespace server {
    enum struct MessageType : std::uint8_t {
        Joined,
        Ping
    };

    struct JoinedPacket {
        MessageType type = MessageType::Joined;
    };

    struct PingPacket {
        MessageType type = MessageType::Ping;
    };
}

// Handle the messages which the client receives from the server
namespace client {
    class JoinedPacketHandler : public PacketHandler<server::MessageType> {
    public:
        bool Handle(MyNetworker* networker) override {
            const auto serverIpAddressString =  networker->GetSenderIpAddress().getPublicAddress().toString();
            puts("I am connected to the server!\n");
            printf("Server IP: %s\n", serverIpAddressString.c_str());
            printf("Server Port: %d\n", networker->GetSenderPort());
            return true;
        }
    };

    class PingPacketHandler : public PacketHandler<server::MessageType> {
    public:
        bool Handle(MyNetworker* networker) override {
            puts("Pinged! Sending a pong.");
            networker->Send(PongPacket());
            return true;
        }
    };
}

// Handle the messages which the server receives from the client
namespace server {
    class JoinRequestPacketHandler : public PacketHandler<client::MessageType> {
    public:
        bool Handle(MyNetworker* networker) override {
            if (state == nullptr) {
                puts("Error: state pointer not set");
                return false;
            }

            const auto clientIpAddressString = networker->GetSenderIpAddress().getPublicAddress().toString();
            puts("A client wishes to connect.");
            printf("Client IP: %s\n", clientIpAddressString.c_str());
            printf("Client Port: %d\n", networker->GetSenderPort());
            
            // Send an 'OK' message.
            if (networker->Send(JoinedPacket())) {
                puts("Sent an OK message");
                // Add the user!
                state->AddUser(networker->GetSenderIpAddress(), networker->GetSenderPort());
            } else {
                puts("Could not send an OK message");
            }
            return true;
        }


        // We interact with the server state easily using a pointer
        ServerState* state {};
    };

    class PongPacketHandler : public PacketHandler<client::MessageType> {
    public:
        bool Handle(MyNetworker* networker) override {
            puts("A client has pinged!");
            // (Here, we can update the 'last ping time' for pruning of laggy clients.)
            return true;
        }

    };
}

const sf::IpAddress ServerIp = "localhost";
const unsigned short ServerPort = 12345;

int Client() {
    sf::UdpSocket socket;
    if (!NonBlockingSocket(socket, ServerIp, sf::Socket::AnyPort)) {
        return EXIT_FAILURE;
    }

    // Set up handlers
    client::JoinedPacketHandler joinedHandler;
    client::PingPacketHandler pingHandler;

    // Set up networkers
    Networker<server::MessageType> networker;
    networker.RegisterHandler(server::MessageType::Joined, &joinedHandler);
    networker.RegisterHandler(server::MessageType::Ping, &pingHandler);
    networker.RegisterSocket(&socket);

    networker.Send(client::JoinRequestPacket(), ServerIp, ServerPort);

    while (true) {
        for (; networker.Receive(); );
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    return EXIT_SUCCESS;
}

int Server() {
    ServerState state;
    sf::UdpSocket socket;
    if (!NonBlockingSocket(socket, ServerIp, ServerPort)) {
        return EXIT_FAILURE;
    }

    // Set up handlers
    server::JoinRequestPacketHandler joinRequestHandler;
    server::PongPacketHandler pongPacketHandler;
    joinRequestHandler.state = &state;

    // Set up networkers
    Networker<client::MessageType> networker;
    networker.RegisterHandler(client::MessageType::JoinRequest, &joinRequestHandler);
    networker.RegisterHandler(client::MessageType::Pong, &pongPacketHandler);
    networker.RegisterSocket(&socket);

    while (true) {
        for (; networker.Receive(); );
        
        // Send a ping message to all clients!
        for (const auto& [userId, userData] : state.users) {
            networker.Send(server::PingPacket(), userData->ipAddress, userData->port);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    return EXIT_SUCCESS;
}

int main() {
    puts("(s)erver or (c)lient?");
    if (getchar() == 's') {
        return Server();
    } else {
        return Client();
    }
}