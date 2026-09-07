// This file Copyright (C) 2026.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.

#pragma once

#ifndef __TRANSMISSION__
#error only libtransmission should #include this header.
#endif

#include <array> // std::array
#include <chrono> // std::chrono::steady_clock
#include <cstddef> // size_t, std::byte
#include <cstdint> // uint8_t
#include <map>
#include <optional>

#ifdef _WIN32
#include <winsock2.h> // sockaddr, socklen_t
#else
#include <sys/socket.h> // sockaddr, socklen_t
#endif

#include "libtransmission/net.h" // tr_socket_address, tr_socket_t
#include "libtransmission/transmission.h" // tr_proxy_protocol_mode

namespace tr::test
{

class ProxyProtocolTest;

} // namespace tr::test

namespace tr::proxy_protocol
{
    // PROXY protocol v2 signature -- the first 12 bytes of every v2 header.
    // Declared here (not in the .cc) so the unit tests build v2 headers from
    // the same bytes the parser matches against.
    inline constexpr std::array<std::byte, 12> V2Signature = {
        std::byte{ 0x0D }, std::byte{ 0x0A }, std::byte{ 0x0D }, std::byte{ 0x0A }, std::byte{ 0x00 },
        std::byte{ 0x0D }, std::byte{ 0x0A }, std::byte{ 0x51 }, std::byte{ 0x55 }, std::byte{ 0x49 },
        std::byte{ 0x54 }, std::byte{ 0x0A },
    };

    // How connections that lack a PROXY protocol header are treated.
    // Maps 1:1 onto tr_proxy_protocol_mode (transmission.h).
    enum class ParseResult : uint8_t
    {
        NotHeader, // data does not start with a PROXY protocol header
        Complete, // data starts with a complete PROXY protocol header
        Incomplete // data starts with a header prefix, but the header is not fully buffered
    };

    struct HeaderInfo
    {
        tr_socket_address source; // SRC address carried by the header; invalid for LOCAL/UNKNOWN
        size_t header_len; // total header size in bytes; strip this many bytes from the stream
    };

    // Parse a PROXY protocol header at the beginning of [data, data + len).
    // PROXY protocol v1 (text) and v2 (binary) are supported.
    [[nodiscard]] std::pair<ParseResult, std::optional<HeaderInfo>> parse(std::byte const* data, size_t len) noexcept;

    // Session-wide PROXY protocol state: the connection mode plus the UDP
    // real<->actual address mapping used for gost-relayed (PROXY protocol)
    // traffic. All methods are called from the session (libevent) thread only,
    // so no locking is required.
    class Manager
    {
    public:
        explicit Manager(tr_proxy_protocol_mode mode = TR_PROXY_PROTOCOL_OFF) noexcept;

        void setMode(tr_proxy_protocol_mode mode) noexcept
        {
            mode_ = mode;
        }

        [[nodiscard]] tr_proxy_protocol_mode mode() const noexcept
        {
            return mode_;
        }

        // --- TCP: call right after accept(), before creating the peer socket.
        // Peeks the accepted socket; if it starts with a complete PROXY protocol
        // header, consumes the header and rewrites socket_address to the SRC
        // address from the header. Returns false when the connection must be
        // dropped. A connection whose header has not (fully) arrived yet is
        // waited for within a short bounded budget before deciding, so Require
        // mode does not mistake a delayed header for a missing one, and Allow
        // mode does not accept a stream it cannot strip the header from.
        [[nodiscard]] bool handleTcpAccepted(tr_socket_t fd, tr_socket_address& socket_address);

        // --- UDP: call on every inbound datagram, before protocol dispatch.
        // If the datagram is a PROXY protocol header, records the real<->actual
        // address mapping and returns true (caller drops the datagram; gost
        // sends the header in its own datagram, the payload follows in the
        // next one). Otherwise, if the datagram's source address is mapped,
        // rewrites *from / *fromlen to the real client address and returns
        // false (caller dispatches normally).
        [[nodiscard]] bool handleUdpDatagram(void const* buf, size_t len, sockaddr* from, socklen_t* fromlen);

        // --- UDP outbound: if the destination names a relayed (real client)
        // address, rewrites it to the relay's actual address so the reply
        // traverses the relay. Returns the rewritten destination when a mapping
        // exists (refreshing the session timeout), or nullopt when the
        // destination is unmapped and the caller should send as-is.
        [[nodiscard]] std::optional<tr_socket_address> rewriteOutbound(sockaddr const* to);

    private:
        friend class tr::test::ProxyProtocolTest; // for the clock-driven prune tests

        void record(tr_socket_address const& real, tr_socket_address const& actual) noexcept;
        void prune(std::chrono::steady_clock::time_point now) noexcept;

        tr_proxy_protocol_mode mode_ = TR_PROXY_PROTOCOL_OFF;

        struct Session
        {
            tr_socket_address actual;
            std::chrono::steady_clock::time_point last_seen;
        };

        // Two indices over the same mapping, keyed by the real client address
        // and by the relay (actual) address. record() keeps them in sync: every
        // session appears in exactly one entry of each map.
        std::map<tr_socket_address, Session> sessions_; // keyed by the real client address
        std::map<tr_socket_address, tr_socket_address> actual_to_real_; // reverse index

        std::chrono::steady_clock::time_point last_prune_;
    };

    // File-scope socket registry so libdht's sendto hook (which has no session
    // pointer) can reach the owning session's Manager. tr_udp_core registers
    // its sockets at construction and unregisters them at destruction.
    //
    // Invariants (every callback runs on the session thread, so no locking):
    //   - a registered Manager outlives the registration: tr_udp_core instances
    //     come and go (the UDP port can change) while the Manager is a stable
    //     tr_session member, so sockets always map to the session's live Manager;
    //   - the only destruction-time use is ~tr_udp_core erasing entries by fd,
    //     which never dereferences the Manager (that matters because, with the
    //     member order in session.h, the Manager is destroyed before udp_core_);
    //   - register_socket overwrites any stale entry left behind by a closed or
    //     reused fd, so a missed unregister cannot point at a dead Manager.
    void register_socket(tr_socket_t sockfd, Manager& manager);
    void unregister_socket(tr_socket_t sockfd);
    [[nodiscard]] Manager* find_manager(tr_socket_t sockfd) noexcept;
} // namespace tr::proxy_protocol
