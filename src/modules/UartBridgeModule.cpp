#include "UartBridgeModule.h"

#ifdef MESHTASTIC_UART_BRIDGE
#include "Default.h"
#include "MeshService.h"
#include "PositionPrecision.h"
#include "Router.h"
#include "Throttle.h"
#include <algorithm>

#if !defined(ARCH_ESP32) && !defined(NRF52_PROMICRO_DIY)
#error "UART bridge is supported only on ESP32 and nRF52 ProMicro DIY"
#endif
#ifndef UART_BRIDGE_CHANNEL
#define UART_BRIDGE_CHANNEL 0
#endif
#ifndef UART_BRIDGE_RX
#error "UART_BRIDGE_RX must be defined"
#endif
#ifndef UART_BRIDGE_TX
#error "UART_BRIDGE_TX must be defined"
#endif

UartBridgeModule *uartBridgeModule;

UartBridgeModule::UartBridgeModule() : MeshModule("UartBridge"), concurrency::OSThread("UartBridge")
{
    uartBridgeModule = this;
    loopbackOk = true;
    ignoreRequest = true;
#ifdef ARCH_ESP32
    Serial2.setRxBufferSize(2048);
    Serial2.begin(38400, SERIAL_8N1, UART_BRIDGE_RX, UART_BRIDGE_TX);
#else
    Serial2.setPins(UART_BRIDGE_RX, UART_BRIDGE_TX);
    Serial2.begin(38400, SERIAL_8N1);
#endif
    LOG_INFO("UART bridge: RX=%d TX=%d, 38400 8N1, channel=%d", UART_BRIDGE_RX, UART_BRIDGE_TX, UART_BRIDGE_CHANNEL);
}

bool UartBridgeModule::channelReady() const
{
#ifdef UART_BRIDGE_FULL
    if (config.device.role != meshtastic_Config_DeviceConfig_Role_CLIENT ||
        config.device.rebroadcast_mode != meshtastic_Config_DeviceConfig_RebroadcastMode_ALL)
        return false;
#endif
    if (!config.lora.use_preset || config.lora.modem_preset != meshtastic_Config_LoRaConfig_ModemPreset_LONG_FAST ||
        UART_BRIDGE_CHANNEL >= channels.getNumChannels())
        return false;
    const auto &ch = channels.getByIndex(UART_BRIDGE_CHANNEL);
    return ch.has_settings && ch.role != meshtastic_Channel_Role_DISABLED &&
           strcmp(channels.getName(UART_BRIDGE_CHANNEL), "LongFast") == 0;
}

bool UartBridgeModule::wantPacket(const meshtastic_MeshPacket *p)
{
#ifdef UART_BRIDGE_FULL
    (void)p;
    return false;
#else
    return channelReady() && p->channel == UART_BRIDGE_CHANNEL && UartBridge::allowedPacket(*p) &&
           (p->transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL ||
            p->transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_API ||
            p->transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA);
#endif
}

#ifdef UART_BRIDGE_FULL
void UartBridgeModule::forwardFull(const meshtastic_MeshPacket &p)
{
    if (!channelReady() || isToUs(&p) || !p.hop_limit || txCount == 4 ||
        (p.transport_mechanism != meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA && !isFromUs(&p)))
        return;
    if (p.which_payload_variant == meshtastic_MeshPacket_decoded_tag && p.channel != UART_BRIDGE_CHANNEL)
        return;
    meshtastic_MeshPacket forwarded = meshtastic_MeshPacket_init_zero;
    forwarded.from = getFrom(&p);
    forwarded.to = p.to;
    forwarded.id = p.id;
    forwarded.channel = p.channel;
    forwarded.hop_limit = p.hop_limit - 1;
    forwarded.hop_start = std::max(p.hop_start, p.hop_limit);
    forwarded.want_ack = p.want_ack;
    forwarded.priority = p.priority;
    forwarded.which_payload_variant = p.which_payload_variant;
    if (p.which_payload_variant == meshtastic_MeshPacket_decoded_tag) {
        forwarded.decoded = p.decoded;
        if (isFromUs(&p)) {
            forwarded.decoded.has_bitfield = true;
            forwarded.decoded.bitfield |= (config.lora.config_ok_to_mqtt << BITFIELD_OK_TO_MQTT_SHIFT);
            forwarded.decoded.bitfield |= (p.decoded.want_response << BITFIELD_WANT_RESPONSE_SHIFT);
        }
    } else {
        forwarded.encrypted = p.encrypted;
        forwarded.pki_encrypted = true;
    }
    if (!UartBridge::allowedFullPacket(forwarded) || !directions.permits(forwarded.from, p.id, false, isBroadcast(p.to)))
        return;
    auto &frame = txQueue[(txHead + txCount) % 4];
    const size_t size = pb_encode_to_bytes(frame.bytes + UartBridge::HEADER_SIZE, UartBridge::MAX_PAYLOAD,
                                           &meshtastic_MeshPacket_msg, &forwarded);
    frame.size = UartBridge::finishFrame(frame.bytes, size);
    if (frame.size) {
        directions.remember(forwarded.from, p.id, false, millis());
        ++txCount;
    }
}
#endif

ProcessMessage UartBridgeModule::handleReceived(const meshtastic_MeshPacket &p)
{
    const uint32_t from = getFrom(&p);
    const uint8_t hopLimit = UartBridge::effectiveHopLimit(p, Default::getConfiguredOrDefaultHopLimit(config.lora.hop_limit));
    if (from <= 1 || from == NODENUM_BROADCAST || !p.id || !hopLimit || seen.contains(from, p.id))
        return ProcessMessage::CONTINUE;
    if (txCount == 4) {
        LOG_WARN("UART bridge: TX queue full, dropping id=0x%08x", p.id);
        return ProcessMessage::CONTINUE;
    }

    meshtastic_MeshPacket forwarded = meshtastic_MeshPacket_init_zero;
    forwarded.from = from;
    forwarded.to = NODENUM_BROADCAST;
    forwarded.id = p.id;
    forwarded.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    forwarded.decoded = p.decoded;
    // Match the originator's encode path before sharing a packet with the same
    // AES nonce.
    if (isFromUs(&p)) {
        if (!applyPositionPrecisionForChannel(forwarded, p.channel))
            return ProcessMessage::CONTINUE;
        forwarded.decoded.has_bitfield = true;
        forwarded.decoded.bitfield |= (config.lora.config_ok_to_mqtt << BITFIELD_OK_TO_MQTT_SHIFT);
        forwarded.decoded.bitfield |= (p.decoded.want_response << BITFIELD_WANT_RESPONSE_SHIFT);
    }
    forwarded.hop_limit = hopLimit - 1;
    forwarded.hop_start = std::max(p.hop_start, hopLimit);

    auto &frame = txQueue[(txHead + txCount) % 4];
    const size_t size = pb_encode_to_bytes(frame.bytes + UartBridge::HEADER_SIZE, UartBridge::MAX_PAYLOAD,
                                           &meshtastic_MeshPacket_msg, &forwarded);
    frame.size = UartBridge::finishFrame(frame.bytes, size);
    if (frame.size) {
        seen.remember(from, p.id);
        ++txCount;
        LOG_DEBUG("UART bridge: queued from=0x%08x id=0x%08x", from, p.id);
    }
    return ProcessMessage::CONTINUE;
}

void UartBridgeModule::receiveFrame()
{
    meshtastic_MeshPacket received = meshtastic_MeshPacket_init_zero;
#ifdef UART_BRIDGE_FULL
    if (!channelReady() || !pb_decode_from_bytes(parser.payload(), parser.payloadSize(), &meshtastic_MeshPacket_msg, &received) ||
        !UartBridge::allowedFullPacket(received) || received.from == nodeDB->getNodeNum() ||
        !directions.permits(received.from, received.id, true, isBroadcast(received.to)))
        return;
    auto p = packetPool.allocZeroed();
    if (!p)
        return;
    p->from = received.from;
    p->to = received.to;
    p->id = received.id;
    p->hop_limit = received.hop_limit;
    p->hop_start = received.hop_start;
    p->want_ack = received.want_ack;
    p->priority = received.priority;
    p->which_payload_variant = received.which_payload_variant;
    if (received.which_payload_variant == meshtastic_MeshPacket_decoded_tag) {
        p->channel = UART_BRIDGE_CHANNEL;
        p->decoded = received.decoded;
    } else {
        p->channel = 0;
        p->encrypted = received.encrypted;
        // Let the destination's ordinary PKI decoder authenticate the sender.
    }
    directions.remember(p->from, p->id, true, millis());
    router->receiveFromBridge(p);
#else
    if (!channelReady() || !pb_decode_from_bytes(parser.payload(), parser.payloadSize(), &meshtastic_MeshPacket_msg, &received) ||
        !UartBridge::allowedPacket(received) || received.from <= 1 || received.from == NODENUM_BROADCAST || !received.id ||
        received.from == nodeDB->getNodeNum() || received.hop_start < received.hop_limit ||
        seen.contains(received.from, received.id))
        return;

    // Build from an allowlist so UART cannot inject routing or local-only
    // metadata.
    auto p = packetPool.allocZeroed();
    if (!p) {
        LOG_WARN("UART bridge: packet pool exhausted");
        return;
    }
    p->from = received.from;
    p->to = NODENUM_BROADCAST;
    p->id = received.id;
    p->channel = UART_BRIDGE_CHANNEL;
    p->which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p->decoded = received.decoded;
    p->hop_limit = received.hop_limit;
    p->hop_start = received.hop_start;
    seen.remember(p->from, p->id);
    LOG_DEBUG("UART bridge: injecting from=0x%08x id=0x%08x", p->from, p->id);
    service->sendToMesh(p, RX_SRC_USER, false);
#endif
}

int32_t UartBridgeModule::runOnce()
{
    if (parser.pending() && !Throttle::isWithinTimespanMs(lastRx, 1000))
        parser.reset();
    for (size_t i = 0; i < 512 && Serial2.available(); ++i) {
        lastRx = millis();
        if (parser.feed(Serial2.read()))
            receiveFrame();
    }
    if (txCount) {
        auto &frame = txQueue[txHead];
        const int available = Serial2.availableForWrite();
        if (available > 0) {
            const size_t count = std::min(frame.size - txPosition, size_t(std::min(available, 32)));
            txPosition += Serial2.write(frame.bytes + txPosition, count);
            if (txPosition == frame.size) {
                txPosition = 0;
                txHead = (txHead + 1) % 4;
                --txCount;
            }
        }
    }
    return 5;
}
#endif
