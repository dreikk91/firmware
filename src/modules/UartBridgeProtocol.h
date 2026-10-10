#pragma once

#include "mesh/Throttle.h"
#include "mesh/generated/meshtastic/mesh.pb.h"
#include <cstddef>
#include <cstdint>

namespace UartBridge
{
constexpr size_t HEADER_SIZE = 5;
constexpr size_t MAX_PAYLOAD = meshtastic_MeshPacket_size;
constexpr size_t MAX_FRAME = HEADER_SIZE + MAX_PAYLOAD + 4;
constexpr uint8_t MAGIC1 = 0xb7, MAGIC2 = 0x4d;
#ifdef UART_BRIDGE_FULL
constexpr uint8_t VERSION = 2;
#else
constexpr uint8_t VERSION = 1;
#endif

inline uint32_t crc32(const uint8_t *bytes, size_t size)
{
    uint32_t crc = 0xffffffff;
    while (size--) {
        crc ^= *bytes++;
        for (unsigned i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ (0xedb88320 & (0u - (crc & 1)));
    }
    return ~crc;
}

inline size_t finishFrame(uint8_t *frame, size_t payloadSize)
{
    if (!payloadSize || payloadSize > MAX_PAYLOAD)
        return 0;
    frame[0] = MAGIC1;
    frame[1] = MAGIC2;
    frame[2] = VERSION;
    frame[3] = static_cast<uint8_t>(payloadSize >> 8);
    frame[4] = static_cast<uint8_t>(payloadSize);
    const uint32_t crc = crc32(frame + 2, payloadSize + 3);
    for (unsigned i = 0; i < 4; ++i)
        frame[HEADER_SIZE + payloadSize + i] = static_cast<uint8_t>(crc >> (24 - 8 * i));
    return HEADER_SIZE + payloadSize + 4;
}

class FrameParser
{
    uint8_t frame[MAX_FRAME] = {};
    size_t position = 0, expected = 0;

  public:
    void reset() { position = expected = 0; }
    bool pending() const { return position != 0; }
    const uint8_t *payload() const { return frame + HEADER_SIZE; }
    size_t payloadSize() const { return expected - HEADER_SIZE - 4; }

    bool feed(uint8_t byte)
    {
        if (position == 0) {
            if (byte == MAGIC1)
                frame[position++] = byte;
            return false;
        }
        if ((position == 1 && byte != MAGIC2) || (position == 2 && byte != VERSION)) {
            reset();
            if (byte == MAGIC1)
                frame[position++] = byte;
            return false;
        }
        frame[position++] = byte;
        if (position == HEADER_SIZE) {
            const size_t size = (size_t(frame[3]) << 8) | frame[4];
            if (!size || size > MAX_PAYLOAD) {
                reset();
                return false;
            }
            expected = HEADER_SIZE + size + 4;
        }
        if (!expected || position != expected)
            return false;
        uint32_t receivedCrc = 0;
        for (size_t i = expected - 4; i < expected; ++i)
            receivedCrc = (receivedCrc << 8) | frame[i];
        position = 0;
        return receivedCrc == crc32(frame + 2, expected - 6);
    }
};

inline uint8_t effectiveHopLimit(const meshtastic_MeshPacket &p, uint8_t defaultHopLimit)
{
    return p.from == 0 && p.want_ack && p.hop_limit == 0 ? defaultHopLimit : p.hop_limit;
}

inline bool allowedPacket(const meshtastic_MeshPacket &p)
{
    if (p.which_payload_variant != meshtastic_MeshPacket_decoded_tag || p.to != UINT32_MAX || p.pki_encrypted ||
        p.public_key.size || p.via_mqtt || p.decoded.dest || p.decoded.source || p.hop_limit > 7 || p.hop_start > 7 ||
        p.decoded.payload.size > sizeof(p.decoded.payload.bytes))
        return false;
    switch (p.decoded.portnum) {
    case meshtastic_PortNum_TEXT_MESSAGE_APP:
    case meshtastic_PortNum_NODEINFO_APP:
    case meshtastic_PortNum_POSITION_APP:
    case meshtastic_PortNum_TELEMETRY_APP:
        return true;
    default:
        return false;
    }
}

inline bool allowedFullPacket(const meshtastic_MeshPacket &p)
{
    if (p.from <= 1 || p.from == UINT32_MAX || p.to <= 1 || !p.id || p.via_mqtt || p.hop_limit > 7 || p.hop_start > 7 ||
        p.hop_start < p.hop_limit)
        return false;
    if (p.which_payload_variant == meshtastic_MeshPacket_encrypted_tag)
        return p.channel == 0 && p.to != UINT32_MAX && p.encrypted.size > 12 && p.encrypted.size <= sizeof(p.encrypted.bytes);
    return p.which_payload_variant == meshtastic_MeshPacket_decoded_tag && !p.pki_encrypted && !p.public_key.size &&
           p.decoded.portnum != meshtastic_PortNum_UNKNOWN_APP && p.decoded.payload.size <= sizeof(p.decoded.payload.bytes);
}

class DirectionCache
{
    struct Entry {
        uint32_t from = 0, id = 0, last = 0;
        bool imported = false;
    } entries[128];
    size_t next = 0;

  public:
    bool permits(uint32_t from, uint32_t id, bool imported, bool broadcast) const
    {
        for (const auto &entry : entries) {
            if (entry.from == from && entry.id == id)
                return entry.imported == imported && !broadcast && !Throttle::isWithinTimespanMs(entry.last, 2000);
        }
        return true;
    }
    void remember(uint32_t from, uint32_t id, bool imported, uint32_t now)
    {
        for (auto &entry : entries) {
            if (entry.from == from && entry.id == id) {
                entry.last = now;
                return;
            }
        }
        entries[next] = {from, id, now, imported};
        next = (next + 1) % 128;
    }
    bool hasImportedFrom(uint32_t from) const
    {
        for (const auto &entry : entries)
            if (entry.from == from && entry.imported)
                return true;
        return false;
    }
};

class SeenPackets
{
    struct Entry {
        uint32_t from = 0, id = 0;
    } entries[128];
    size_t next = 0;

  public:
    bool contains(uint32_t from, uint32_t id) const
    {
        for (const auto &entry : entries)
            if (entry.from == from && entry.id == id)
                return true;
        return false;
    }
    void remember(uint32_t from, uint32_t id)
    {
        entries[next] = {from, id};
        next = (next + 1) % 128;
    }
};
} // namespace UartBridge
