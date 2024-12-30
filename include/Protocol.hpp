#pragma once

#include <cstdint>
#include "SecureTypes.hpp"

namespace secure_comm {

// Protocol version
constexpr uint32_t PROTOCOL_VERSION = 1;

// Message types for protocol communication
enum class MessageType : uint16_t {
    DATA = 1,
    KEY_RENEWAL_REQUEST = 2,
    KEY_RENEWAL_RESPONSE = 3,
    ERROR = 4
};

// Message header structures
#pragma pack(push, 1)
struct MessageHeader {
    uint32_t version;
    MessageType type;
    uint32_t payloadSize;
    uint64_t timestamp;
    uint8_t flags;
    uint8_t reserved[3];
};

struct ProtocolHeader {
    uint16_t version;
    MessageType type;
    uint32_t payload_size;
    uint32_t sequence_number;
} __attribute__((packed));
#pragma pack(pop)

// Protocol-specific constants
namespace protocol {
    constexpr size_t HEADER_SIZE = sizeof(MessageHeader);
    constexpr size_t MAX_PAYLOAD_SIZE = SecurityParameters::MAX_MESSAGE_SIZE - HEADER_SIZE;
    constexpr uint8_t FLAG_ENCRYPTED = 0x01;
    constexpr uint8_t FLAG_COMPRESSED = 0x02;
    constexpr uint8_t FLAG_URGENT = 0x04;
    constexpr uint8_t FLAG_FRAGMENTED = 0x08;
}

} // namespace secure_comm 