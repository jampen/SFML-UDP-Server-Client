#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <type_traits>
#include <SFML/Network.hpp>

namespace udp
{

template<typename MessageType>
class Networker {
    static_assert(std::is_enum<MessageType>::value, "MessageType must be an enum");
    static_assert(sizeof(MessageType) == sizeof(std::uint8_t), "MessageType must be a byte in size");
public:
    using Self = Networker<MessageType>;
    using PacketHandler = std::function<bool()>;

public:
    bool Bind
    (
        const sf::IpAddress ipAddress = "localhost", 
        const unsigned short port = sf::Socket::AnyPort
    )   {
        if (socket.bind(port, ipAddress) == sf::Socket::Done) {
            socket.setBlocking(false);
            return true;
        } else {
            return false;
        }
    }

    // Recieves messages and dispatches them to the handlers
    bool Receive() {
        std::size_t numBytesRecieved;

        const auto receiveStatus = socket.receive
        (
            buffer.data(),
            buffer.size(),
            numBytesRecieved,
            senderAddress,
            senderPort
        );

        switch (receiveStatus) {
          case sf::Socket::Done: 
                return DispatchPacket();
            case sf::Socket::Error:
                ReportError();
                return false;
            default:
                return false;
        }
    }

    template<typename Packet> Packet GetPacket() const {
        return *reinterpret_cast<const Packet*>(buffer.data());
    }

    void RegisterHandler(const MessageType message, PacketHandler handler) {
        dispatchers[message] = handler;
    }

    template<typename Packet>
    bool Send
    (   const Packet& packet,
        const sf::IpAddress ipAddress,
        const unsigned short port
    ) {
        return sf::Socket::Done == socket.send(&packet, sizeof(packet), ipAddress, port);
    }

    template<typename Packet>
    bool Send(const Packet& packet) {
        return Send(packet, senderAddress, senderPort);
    }

    auto GetSenderIpAddress() const { return senderAddress; }
    auto GetSenderPort() const { return senderPort; }

private:
    bool DispatchPacket() {
        // Find a dispatcher for the message
        const auto messageType = static_cast<MessageType>(buffer.at(0));
        if (const auto dispatcherIterator = dispatchers.find(messageType); dispatcherIterator != dispatchers.end())
        {
            const auto& [_, dispatcher] = *dispatcherIterator;
            return dispatcher();
        }

        // No dispatcher found
        return false;
    }

    void ReportError() {
        const auto senderIpAddressString = senderAddress.toString();
        fprintf(stderr, 
            "There was an error receiving a packet\n"
            "Sender IP: %s\n"
            "Sender Port: %d\n",
            senderIpAddressString.c_str(),
            static_cast<int>(senderPort)
        );
    }

private:
    constexpr static int BufferSize = 8192;
    sf::UdpSocket socket;

    // Info about the sender from the last received packet
    sf::IpAddress senderAddress;
    unsigned short senderPort;
    
    std::unordered_map<MessageType, PacketHandler> dispatchers;
    std::array<std::uint8_t, BufferSize> buffer;
};

}