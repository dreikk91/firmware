#pragma once

#include "configuration.h"

#ifdef MESHTASTIC_UART_BRIDGE
#include "MeshModule.h"
#include "UartBridgeProtocol.h"
#include "concurrency/OSThread.h"

class UartBridgeModule : public MeshModule, private concurrency::OSThread
{
    struct TxFrame {
        uint8_t bytes[UartBridge::MAX_FRAME];
        size_t size = 0;
    } txQueue[4];
    size_t txHead = 0, txCount = 0, txPosition = 0;
    UartBridge::FrameParser parser;
    UartBridge::SeenPackets seen;
#ifdef UART_BRIDGE_FULL
    UartBridge::DirectionCache directions;
#endif
    uint32_t lastRx = 0;

    bool channelReady() const;
    void receiveFrame();

  public:
    UartBridgeModule();
#ifndef UART_BRIDGE_FULL
    void forwardPublic(const meshtastic_MeshPacket &p, const meshtastic_MeshPacket *wire = nullptr);
#endif
#ifdef UART_BRIDGE_FULL
    void forwardFull(const meshtastic_MeshPacket &p, const meshtastic_MeshPacket *wire = nullptr);
    bool isRemoteNode(uint32_t from) const { return directions.hasImportedFrom(from); }
#endif

  protected:
    bool wantPacket(const meshtastic_MeshPacket *p) override;
    ProcessMessage handleReceived(const meshtastic_MeshPacket &p) override;
    int32_t runOnce() override;
};
extern UartBridgeModule *uartBridgeModule;
#endif
