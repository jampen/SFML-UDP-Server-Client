#include "udp/Networker.hpp"
#include <thread>

const unsigned short ServerPort = 12345;

enum struct ServerMessage : std::uint8_t {
    Joined,
    Ping
};

enum struct ClientMessage : std::uint8_t {
    JoinRequest,
    SendNumber
};

struct SendNumber {
    ClientMessage message { ClientMessage::SendNumber };
    int number{};
};

int Client() {
    udp::Networker<ServerMessage> networker;
    if (!networker.Bind(sf::IpAddress::Any, sf::Socket::AnyPort)) {
        exit(EXIT_FAILURE);
    }

    networker.Send(ClientMessage::JoinRequest, "localhost", ServerPort);
    
    networker.RegisterHandler(ServerMessage::Joined, [](){
        puts("Joined the server");
        return true;
    });

    networker.RegisterHandler(ServerMessage::Ping, [&](){
        puts("Pinged");

        // Demonstrate sending structs over the network
        SendNumber packet;
        packet.number = rand() % 100;
        networker.Send(packet);
        return true;
    });

    while (true) {
        // Handle incoming packets
        for (; networker.Receive(); );
    }
}

int Server() {
    udp::Networker<ClientMessage> networker;
    if (!networker.Bind(sf::IpAddress::Any, ServerPort)) {
        exit(EXIT_FAILURE);
    }

    struct User {
        sf::IpAddress ip;
        unsigned short port;
    };

    std::vector<User> users;

    networker.RegisterHandler(ClientMessage::JoinRequest, [&](){
        puts("A user has joined the server");
        users.push_back({.ip = networker.GetSenderIpAddress(), .port = networker.GetSenderPort()});
        networker.Send(ServerMessage::Joined);
        return true;
    });

    networker.RegisterHandler(ClientMessage::SendNumber, [&](){
        // Demonstrate receiving structs
        const auto packet = networker.GetPacket<SendNumber>();
        printf("A user sent the number: %d\n", packet.number);
        return true;
    });



    while (true) {
        // Handle incoming packets
        for (; networker.Receive(); );

        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        for (const auto& [userIp, userPort]: users) {
            networker.Send(ServerMessage::Ping, userIp, userPort);
        }
    }
}

int main() {
    puts("(c)lient or (s)erver?");
    if (getchar() == 'c') {
        return Client();        
    } else {
        return Server();
    }
}