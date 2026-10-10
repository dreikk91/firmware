// UART framing and policy tests for UartBridgeProtocol.h. Signed Data and ACK proofs
// must survive protobuf transport unchanged; partial signatures and old frames are rejected.
#include "modules/UartBridgeProtocol.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <pb_decode.h>
#include <pb_encode.h>

#ifdef UNIT_TEST
#include <unity.h>
#undef assert
#define assert(condition) TEST_ASSERT_TRUE(condition)
void setUp() {}
void tearDown() {}
#endif

using namespace UartBridge;

#ifdef UART_BRIDGE_HOST_TEST
static uint32_t testClock;
bool Throttle::isWithinTimespanMs(uint32_t last, uint32_t interval)
{
    return uint32_t(testClock - last) < interval;
}
#endif

static void testFullPackets()
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.from = 0x12345678;
    p.to = 0x87654321;
    p.id = 20;
    p.hop_start = 3;
    p.hop_limit = 2;
    p.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    const meshtastic_PortNum ports[] = {meshtastic_PortNum_TEXT_MESSAGE_APP, meshtastic_PortNum_TELEMETRY_APP,
                                        meshtastic_PortNum_TRACEROUTE_APP,   meshtastic_PortNum_ROUTING_APP,
                                        meshtastic_PortNum_ADMIN_APP,        meshtastic_PortNum_SERIAL_APP,
                                        meshtastic_PortNum_PRIVATE_APP};
    for (auto port : ports) {
        p.decoded.portnum = port;
        assert(allowedFullPacket(p));
        auto broadcast = p;
        broadcast.to = UINT32_MAX;
        assert(allowedFullPacket(broadcast));
    }
    p.pki_encrypted = true;
    assert(!allowedFullPacket(p));
    p.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    p.channel = 0;
    p.encrypted.size = 40;
    assert(allowedFullPacket(p));
    auto invalid = p;
    invalid.channel = 1;
    assert(!allowedFullPacket(invalid));
    invalid = p;
    invalid.to = UINT32_MAX;
    assert(!allowedFullPacket(invalid));
    invalid = p;
    invalid.encrypted.size = 12;
    assert(!allowedFullPacket(invalid));
    invalid = p;
    invalid.encrypted.size = sizeof(invalid.encrypted.bytes) + 1;
    assert(!allowedFullPacket(invalid));
    invalid = p;
    invalid.from = 0;
    assert(!allowedFullPacket(invalid));
    invalid = p;
    invalid.hop_start = 1;
    assert(!allowedFullPacket(invalid));
    p.hop_limit = 0;
    assert(allowedFullPacket(p));
}

#ifdef UART_BRIDGE_HOST_TEST
static void testDirectionalRetries()
{
    DirectionCache cache;
    testClock = 100;
    assert(cache.permits(10, 50, false, false));
    cache.remember(10, 50, false, testClock);
    assert(!cache.permits(10, 50, true, false));
    assert(!cache.permits(10, 50, false, false));
    testClock = 2100;
    assert(cache.permits(10, 50, false, false));
    assert(!cache.permits(10, 50, true, false));
    assert(!cache.permits(10, 50, false, true));
    cache.remember(11, 50, true, testClock);
    assert(cache.hasImportedFrom(11));
    testClock += 2000;
    assert(cache.permits(11, 50, true, false));
    assert(!cache.permits(11, 50, false, false));
    testClock = UINT32_MAX - 1000;
    cache.remember(12, 50, true, testClock);
    testClock = 998;
    assert(!cache.permits(12, 50, true, false));
    testClock = 999;
    assert(cache.permits(12, 50, true, false));
    for (uint32_t i = 0; i < 128; ++i)
        cache.remember(100, i + 1, true, testClock);
    assert(!cache.hasImportedFrom(11));
}
#endif

static size_t feed(FrameParser &parser, const uint8_t *bytes, size_t size)
{
    size_t count = 0;
    for (size_t i = 0; i < size; ++i)
        count += parser.feed(bytes[i]);
    return count;
}

static void testFrames()
{
    const char *reference = "123456789";
    assert(crc32(reinterpret_cast<const uint8_t *>(reference), 9) == 0xcbf43926);
    uint8_t frame[MAX_FRAME] = {};
    for (size_t i = 0; i < MAX_PAYLOAD; ++i)
        frame[HEADER_SIZE + i] = static_cast<uint8_t>(i);
    const size_t size = finishFrame(frame, MAX_PAYLOAD);
    assert(size == MAX_FRAME);
    FrameParser parser;
    assert(feed(parser, frame, size) == 1);
    for (uint8_t version = 1; version <= 4; ++version) {
        if (version == VERSION)
            continue;
        frame[2] = version;
        const uint32_t crc = crc32(frame + 2, MAX_PAYLOAD + 3);
        for (unsigned i = 0; i < 4; ++i)
            frame[HEADER_SIZE + MAX_PAYLOAD + i] = static_cast<uint8_t>(crc >> (24 - 8 * i));
        parser.reset();
        assert(feed(parser, frame, size) == 0);
    }
    frame[2] = VERSION;
    finishFrame(frame, MAX_PAYLOAD);
    parser.reset();
    assert(feed(parser, frame, size) == 1);
    assert(parser.payloadSize() == MAX_PAYLOAD);
    assert(memcmp(parser.payload(), frame + HEADER_SIZE, MAX_PAYLOAD) == 0);
    assert(feed(parser, frame, size) == 1);

    for (size_t i = HEADER_SIZE; i < size; ++i) {
        frame[i] ^= 1;
        parser.reset();
        assert(feed(parser, frame, size) == 0);
        frame[i] ^= 1;
        assert(feed(parser, frame, size) == 1);
    }
    const uint8_t noise[] = {0, 0xff, MAGIC1, MAGIC1, MAGIC2, 99, MAGIC1};
    parser.reset();
    assert(feed(parser, noise, sizeof(noise)) == 0);
    assert(feed(parser, frame, size) == 1);
    const uint8_t oversized[] = {MAGIC1, MAGIC2, VERSION, 0xff, 0xff};
    assert(feed(parser, oversized, sizeof(oversized)) == 0);
    assert(!parser.pending());
    assert(feed(parser, frame, size) == 1);
    const uint8_t empty[] = {MAGIC1, MAGIC2, VERSION, 0, 0};
    assert(feed(parser, empty, sizeof(empty)) == 0);
    assert(feed(parser, frame, size / 2) == 0);
    assert(parser.pending());
    parser.reset();
    assert(feed(parser, frame, size) == 1);
    assert(finishFrame(frame, 0) == 0);
    assert(finishFrame(frame, MAX_PAYLOAD + 1) == 0);
}

static void test_signed_data_roundtrip()
{
    meshtastic_MeshPacket sent = meshtastic_MeshPacket_init_zero;
    sent.from = 0x12345678;
    sent.to = UINT32_MAX;
    sent.id = 0x87654321;
    sent.hop_start = 3;
    sent.hop_limit = 2;
    sent.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    sent.decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
    sent.decoded.has_bitfield = true;
    sent.decoded.bitfield = 3;
    sent.decoded.want_response = true;
    sent.decoded.request_id = 0x456789ab;
    sent.decoded.reply_id = 0x56789abc;
    sent.decoded.emoji = 0x1234;
    sent.decoded.payload.size = 20;
    sent.decoded.xeddsa_signature.size = 64;
    for (unsigned i = 0; i < 64; ++i)
        sent.decoded.xeddsa_signature.bytes[i] = static_cast<uint8_t>(i);
    assert(allowedPacket(sent));
    assert(allowedFullPacket(sent));
    uint8_t frame[MAX_FRAME] = {};
    auto output = pb_ostream_from_buffer(frame + HEADER_SIZE, MAX_PAYLOAD);
    assert(pb_encode(&output, meshtastic_MeshPacket_fields, &sent));
    const size_t size = finishFrame(frame, output.bytes_written);
    FrameParser parser;
    assert(feed(parser, frame, size) == 1);
    auto input = pb_istream_from_buffer(parser.payload(), parser.payloadSize());
    meshtastic_MeshPacket received = meshtastic_MeshPacket_init_zero;
    assert(pb_decode(&input, meshtastic_MeshPacket_fields, &received));
    assert(received.from == sent.from && received.to == sent.to && received.id == sent.id);
    assert(memcmp(&received.decoded, &sent.decoded, sizeof(sent.decoded)) == 0);
    for (pb_size_t i = 1; i < 64; ++i) {
        received.decoded.xeddsa_signature.size = i;
        assert(!allowedPacket(received));
        assert(!allowedFullPacket(received));
    }
    sent.decoded.portnum = meshtastic_PortNum_ROUTING_APP;
    meshtastic_Routing ack = meshtastic_Routing_init_zero;
    ack.which_variant = meshtastic_Routing_error_reason_tag;
    ack.error_reason = meshtastic_Routing_Error_NONE;
    ack.ack_proof.size = sizeof(ack.ack_proof.bytes);
    memset(ack.ack_proof.bytes, 0xa5, ack.ack_proof.size);
    output = pb_ostream_from_buffer(sent.decoded.payload.bytes, sizeof(sent.decoded.payload.bytes));
    assert(pb_encode(&output, meshtastic_Routing_fields, &ack));
    sent.decoded.payload.size = static_cast<pb_size_t>(output.bytes_written);
    output = pb_ostream_from_buffer(frame + HEADER_SIZE, MAX_PAYLOAD);
    assert(pb_encode(&output, meshtastic_MeshPacket_fields, &sent));
    assert(feed(parser, frame, finishFrame(frame, output.bytes_written)) == 1);
    input = pb_istream_from_buffer(parser.payload(), parser.payloadSize());
    assert(pb_decode(&input, meshtastic_MeshPacket_fields, &received));
    meshtastic_Routing decodedAck = meshtastic_Routing_init_zero;
    input = pb_istream_from_buffer(received.decoded.payload.bytes, received.decoded.payload.size);
    assert(pb_decode(&input, meshtastic_Routing_fields, &decodedAck));
    assert(decodedAck.ack_proof.size == ack.ack_proof.size);
    assert(memcmp(decodedAck.ack_proof.bytes, ack.ack_proof.bytes, ack.ack_proof.size) == 0);
    sent.to = 0x3456789a;
    sent.channel = 0;
    sent.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    sent.pki_encrypted = true;
    sent.encrypted.size = 40;
    for (unsigned i = 0; i < sent.encrypted.size; ++i)
        sent.encrypted.bytes[i] = static_cast<uint8_t>(i);
    assert(allowedFullPacket(sent));
    assert(!allowedPacket(sent));
    output = pb_ostream_from_buffer(frame + HEADER_SIZE, MAX_PAYLOAD);
    assert(pb_encode(&output, meshtastic_MeshPacket_fields, &sent));
    assert(feed(parser, frame, finishFrame(frame, output.bytes_written)) == 1);
    input = pb_istream_from_buffer(parser.payload(), parser.payloadSize());
    assert(pb_decode(&input, meshtastic_MeshPacket_fields, &received));
    assert(received.encrypted.size == sent.encrypted.size);
    assert(memcmp(received.encrypted.bytes, sent.encrypted.bytes, sent.encrypted.size) == 0);
}

static void testPrivacyFilter()
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.to = UINT32_MAX;
    p.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    const meshtastic_PortNum allowed[] = {meshtastic_PortNum_TEXT_MESSAGE_APP, meshtastic_PortNum_NODEINFO_APP,
                                          meshtastic_PortNum_POSITION_APP, meshtastic_PortNum_TELEMETRY_APP};
    for (auto port : allowed) {
        p.decoded.portnum = port;
        assert(allowedPacket(p));
    }
    const meshtastic_PortNum blocked[] = {meshtastic_PortNum_ADMIN_APP, meshtastic_PortNum_ROUTING_APP,
                                          meshtastic_PortNum_TRACEROUTE_APP, meshtastic_PortNum_SERIAL_APP,
                                          meshtastic_PortNum_PRIVATE_APP};
    for (auto port : blocked) {
        p.decoded.portnum = port;
        assert(!allowedPacket(p));
    }
    p.decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
    auto invalid = p;
    invalid.to = 0x12345678;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.to = 1;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.pki_encrypted = true;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.public_key.size = 32;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.decoded.dest = 0x12345678;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.decoded.source = 0x12345678;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.via_mqtt = true;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.hop_limit = 8;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.hop_start = 8;
    assert(!allowedPacket(invalid));
    invalid = p;
    invalid.decoded.payload.size = sizeof(invalid.decoded.payload.bytes) + 1;
    assert(!allowedPacket(invalid));
    p.hop_limit = 0;
    assert(allowedPacket(p));
}

static void testHopBudget()
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.want_ack = true;
    assert(effectiveHopLimit(p, 3) == 3);
    p.hop_limit = 2;
    assert(effectiveHopLimit(p, 3) == 2);
    p.hop_limit = 0;
    p.want_ack = false;
    assert(effectiveHopLimit(p, 3) == 0);
    p.from = 0x12345678;
    p.want_ack = true;
    assert(effectiveHopLimit(p, 3) == 0);
    p.hop_limit = 1;
    assert(effectiveHopLimit(p, 3) == 1);
}

static void testDuplicates()
{
    SeenPackets seen;
    seen.remember(10, 50);
    assert(seen.contains(10, 50));
    assert(!seen.contains(11, 50));
    assert(!seen.contains(10, 51));
    for (uint32_t i = 0; i < 128; ++i)
        seen.remember(100, i + 1);
    assert(!seen.contains(10, 50));
    for (uint32_t i = 0; i < 128; ++i)
        assert(seen.contains(100, i + 1));
}

int main()
{
#ifdef UNIT_TEST
    UNITY_BEGIN();
    RUN_TEST(testFrames);
    RUN_TEST(testPrivacyFilter);
    RUN_TEST(testHopBudget);
    RUN_TEST(testDuplicates);
    RUN_TEST(testFullPackets);
    RUN_TEST(test_signed_data_roundtrip);
    return UNITY_END();
#else
    testFrames();
    testPrivacyFilter();
    testHopBudget();
    testDuplicates();
    testFullPackets();
    test_signed_data_roundtrip();
#ifdef UART_BRIDGE_HOST_TEST
    testDirectionalRetries();
#endif
    printf("UART bridge v%u: framing/CRC, policies, hops, retries, signature and ACK proof transport passed\n", VERSION);
#endif
}
