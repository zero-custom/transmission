// This file Copyright (C) 2026.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.

// PROXY protocol (HAProxy) support for gost-relayed peer connections.
//
// gost injects a PROXY protocol header at the start of every relayed stream
// (TCP) or as the first datagram of every relayed UDP session, describing the
// original client address. Without parsing it, transmission sees gost's own
// address instead of the real client's. This module:
//   - parses v1 (text) and v2 (binary) headers (see https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
//   - strips the header from accepted TCP streams and rewrites the peer address
//   - records a real<->actual address mapping for relayed UDP sessions and
//     rewrites both directions, so µTP/DHT see the real client while replies
//     still traverse the gost relay instead of dying in the bridge network.

#include "libtransmission/proxy-protocol.h"

#include <array>
#include <cerrno> // errno, EAGAIN, EWOULDBLOCK
#include <charconv> // std::from_chars
#include <chrono> // std::chrono literals
#include <cstring> // std::memcpy
#include <string_view>
#include <utility>

#ifndef _WIN32
#include <poll.h> // poll(), pollfd
#endif

#include <fmt/format.h>

#include "libtransmission/log.h"

using namespace std::literals;

namespace tr::proxy_protocol
{
    namespace
    {
        // v2 fixed header: 12-byte signature + version/command + family/proto + 2-byte length.
        constexpr size_t V2FixedHeaderLen = 16;

        // v1 headers are at most 107 bytes including the trailing CRLF (spec).
        constexpr size_t V1MaxHeaderLen = 107;

        // Enough to hold any v1 header and every sane v2 address block.
        constexpr size_t MaxPeekLen = 512;

        // How long handleTcpAccepted waits for a complete PROXY protocol header.
        // gost writes the header right after opening the upstream connection and
        // the last hop is a local bridge, so by the time accept() is processed
        // the header is normally already buffered; the budget only covers the
        // accept-vs-write race and a header that arrives split across segments.
        // It is bounded so a peer that sends nothing (or only a header prefix)
        // cannot stall the session thread for long.
        auto constexpr TcpHeaderWait = std::chrono::milliseconds{ 250 };

        [[nodiscard]] bool would_block() noexcept
        {
#ifdef _WIN32
            return WSAGetLastError() == WSAEWOULDBLOCK;
#else
            return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
        }

#ifndef _WIN32
        // Wait until `fd` becomes readable or `deadline` passes. Returns true
        // when the socket became readable and more bytes may be available.
        [[nodiscard]] bool wait_readable(tr_socket_t fd, std::chrono::steady_clock::time_point deadline) noexcept
        {
            for (;;)
            {
                auto const now = std::chrono::steady_clock::now();
                if (now >= deadline)
                {
                    return false;
                }

                auto pfd = pollfd{ fd, POLLIN, 0 };
                auto const timeout_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
                auto const ret = poll(&pfd, 1, static_cast<int>(timeout_ms));
                if (ret >= 0)
                {
                    return ret > 0 && (pfd.revents & POLLIN) != 0;
                }
                if (errno != EINTR) // poll was interrupted by a signal; retry with the remaining budget
                {
                    return false;
                }
            }
        }
#else
        // Windows is not a gost-relay target; fall back to the single-attempt path.
        [[nodiscard]] bool wait_readable(tr_socket_t, std::chrono::steady_clock::time_point) noexcept
        {
            return false;
        }
#endif

        [[nodiscard]] bool starts_with(std::byte const* data, size_t len, std::string_view prefix) noexcept
        {
            auto const* const bytes = reinterpret_cast<char const*>(data);
            return len >= std::size(prefix) &&
                std::equal(std::data(prefix), std::data(prefix) + std::size(prefix), bytes);
        }

        // data[crlf_pos] == '\r', data[crlf_pos + 1] == '\n'; the line starts
        // with "PROXY ". Returns nullopt when the line is malformed.
        [[nodiscard]] std::optional<HeaderInfo> parse_v1_line(std::byte const* data, size_t crlf_pos) noexcept
        {
            auto const header_len = crlf_pos + 2;
            if (header_len > V1MaxHeaderLen)
            {
                return std::nullopt;
            }

            // Everything between "PROXY " and the CRLF.
            auto const remain = std::string_view{ reinterpret_cast<char const*>(data) + 6, crlf_pos - 6 };
            auto tokens = std::array<std::string_view, 5>{};
            auto n_tokens = size_t{ 0 };
            auto start = size_t{ 0 };

            for (size_t i = 0; i <= std::size(remain) && n_tokens < std::size(tokens); ++i)
            {
                if (i == std::size(remain) || remain[i] == ' ')
                {
                    if (i > start)
                    {
                        tokens[n_tokens++] = remain.substr(start, i - start);
                    }
                    start = i + 1;
                }
            }

            if (n_tokens == 0)
            {
                return std::nullopt;
            }

            if (tokens[0] == "UNKNOWN"sv)
            {
                return HeaderInfo{ {}, header_len };
            }

            if (n_tokens != 5)
            {
                return std::nullopt;
            }

            // PROXY <proto> <src-ip> <dst-ip> <src-port> <dst-port>
            auto const parse_port = [](std::string_view const s) -> std::optional<tr_port>
            {
                auto val = 0U;
                auto const [ptr, ec] = std::from_chars(std::data(s), std::data(s) + std::size(s), val, 10);
                if (ec != std::errc{} || ptr != std::data(s) + std::size(s) || val > 65535U)
                {
                    return std::nullopt;
                }
                return tr_port::from_host(static_cast<uint16_t>(val));
            };

            auto const src = tr_address::from_string(tokens[1]);
            auto const sport = parse_port(tokens[3]);
            if (!src || !sport)
            {
                return std::nullopt;
            }

            if (tokens[0] == "TCP4"sv && src->is_ipv4())
            {
                return HeaderInfo{ tr_socket_address{ *src, *sport }, header_len };
            }
            if (tokens[0] == "TCP6"sv && src->is_ipv6())
            {
                return HeaderInfo{ tr_socket_address{ *src, *sport }, header_len };
            }

            return std::nullopt;
        }

        // data starts with the v2 signature. Returns nullopt when the header
        // (incl. the length-declared address block) is not fully buffered.
        [[nodiscard]] std::optional<HeaderInfo> parse_v2_header(std::byte const* data, size_t len) noexcept
        {
            if (len < V2FixedHeaderLen)
            {
                return std::nullopt;
            }

            auto const ver_cmd = data[12]; // 0x20 = v2 PROXY, 0x21 = v2 LOCAL
            auto const fam = data[13]; // 0x11/0x12 = AF_INET stream/dgram, 0x21/0x22 = AF_INET6
            auto const addr_len = (static_cast<size_t>(data[14]) << 8U) | static_cast<size_t>(data[15]);
            auto const header_len = V2FixedHeaderLen + addr_len;
            if (len < header_len)
            {
                return std::nullopt;
            }

            // LOCAL command and the UNSPEC family carry no client address.
            if (ver_cmd != std::byte{ 0x20 } || fam == std::byte{ 0x00 })
            {
                return HeaderInfo{ {}, header_len };
            }

            auto const* const p = data + V2FixedHeaderLen;
            switch (fam)
            {
            case std::byte{ 0x11 }: // AF_INET, STREAM
            case std::byte{ 0x12 }: // AF_INET, DGRAM
                if (addr_len >= 12)
                {
                    return HeaderInfo{ tr_socket_address::from_compact_ipv4(p).first, header_len };
                }
                break;
            case std::byte{ 0x21 }: // AF_INET6, STREAM
            case std::byte{ 0x22 }: // AF_INET6, DGRAM
                if (addr_len >= 36)
                {
                    return HeaderInfo{ tr_socket_address::from_compact_ipv6(p).first, header_len };
                }
                break;
            default:
                break;
            }

            // Declared family is not AF_INET/6, or the address block is too
            // short: nothing to rewrite, but the header is still consumed.
            return HeaderInfo{ {}, header_len };
        }
    } // namespace

    std::pair<ParseResult, std::optional<HeaderInfo>> parse(std::byte const* data, size_t len) noexcept
    {
        // v2: 12-byte signature + 4-byte fixed header
        if (len >= std::size(V2Signature) &&
            std::equal(std::data(V2Signature), std::data(V2Signature) + std::size(V2Signature), data))
        {
            if (auto const header = parse_v2_header(data, len); header)
            {
                return { ParseResult::Complete, header };
            }
            return { ParseResult::Incomplete, std::nullopt };
        }

        // partial v2 signature
        if (std::equal(data, data + len, std::data(V2Signature), std::data(V2Signature) + len))
        {
            return { ParseResult::Incomplete, std::nullopt };
        }

        // v1: "PROXY " + a single CRLF-terminated line
        if (starts_with(data, len, "PROXY "sv))
        {
            for (size_t i = 6; i + 1 < len; ++i)
            {
                if (data[i] == std::byte{ '\r' } && data[i + 1] == std::byte{ '\n' })
                {
                    if (auto const header = parse_v1_line(data, i); header)
                    {
                        return { ParseResult::Complete, header };
                    }
                    return { ParseResult::NotHeader, std::nullopt };
                }
            }
            return { ParseResult::Incomplete, std::nullopt };
        }

        // partial "PROXY " prefix
        if (len < 6 &&
            std::equal(
                reinterpret_cast<char const*>(data),
                reinterpret_cast<char const*>(data) + len,
                std::data("PROXY "sv)))
        {
            return { ParseResult::Incomplete, std::nullopt };
        }

        return { ParseResult::NotHeader, std::nullopt };
    }

    // --- Manager

    Manager::Manager(tr_proxy_protocol_mode mode) noexcept
        : mode_{ mode }
    {
    }

    void Manager::record(tr_socket_address const& real, tr_socket_address const& actual) noexcept
    {
        auto const now = std::chrono::steady_clock::now();

        // Keep both indices consistent when an address is re-bound. A real that
        // was already mapped to a different actual leaves a stale reverse entry
        // behind (and vice versa), which would otherwise never be reclaimed and
        // could attribute datagrams to the wrong session.
        if (auto const it = sessions_.find(real); it != std::end(sessions_))
        {
            if (!(it->second.actual == actual))
            {
                actual_to_real_.erase(it->second.actual);
            }
            it->second = Session{ actual, now };
        }
        else
        {
            sessions_.emplace(real, Session{ actual, now });
        }

        if (auto const it = actual_to_real_.find(actual); it != std::end(actual_to_real_))
        {
            if (!(it->second == real))
            {
                sessions_.erase(it->second);
            }
            it->second = real;
        }
        else
        {
            actual_to_real_.emplace(actual, real);
        }

        // Opportunistic pruning, at most once a minute.
        if (last_prune_.time_since_epoch().count() == 0 || now - last_prune_ >= std::chrono::minutes{ 1 })
        {
            last_prune_ = now;
            prune(now);
        }
    }

    void Manager::prune(std::chrono::steady_clock::time_point now) noexcept
    {
        // A relayed session that has been idle for 15 minutes is gone; gost
        // closes its relay well before that, and DHT queries are refreshed
        // far more often.
        auto const cutoff = now - std::chrono::minutes{ 15 };

        for (auto it = std::begin(sessions_); it != std::end(sessions_);)
        {
            if (it->second.last_seen < cutoff)
            {
                actual_to_real_.erase(it->second.actual);
                it = sessions_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    bool Manager::handleTcpAccepted(tr_socket_t fd, tr_socket_address& socket_address)
    {
        if (mode_ == TR_PROXY_PROTOCOL_OFF)
        {
            return true;
        }

        auto buf = std::array<std::byte, MaxPeekLen>{};
        auto const deadline = std::chrono::steady_clock::now() + TcpHeaderWait;

        for (;;)
        {
            auto const n_read = recv(fd, reinterpret_cast<char*>(std::data(buf)), std::size(buf), MSG_PEEK);
            if (n_read < 0 && would_block())
            {
                // Nothing buffered yet: accept() fired before the relay's header
                // write arrived. Require mode cannot tell a delayed header from a
                // missing one, so it waits briefly for the header; Allow mode
                // keeps the connection, since a headerless stream is
                // indistinguishable from a plain peer that has not spoken yet.
                if (mode_ == TR_PROXY_PROTOCOL_REQUIRE && wait_readable(fd, deadline))
                {
                    continue;
                }
                return mode_ != TR_PROXY_PROTOCOL_REQUIRE;
            }

            if (n_read <= 0) // orderly EOF or a non-EAGAIN error: nothing more will come
            {
                return false;
            }

            auto const [result, header] = parse(std::data(buf), static_cast<size_t>(n_read));
            if (result == ParseResult::Complete)
            {
                // Consume exactly the header; the payload stays in the kernel buffer.
                (void)recv(fd, reinterpret_cast<char*>(std::data(buf)), header->header_len, 0);
                if (header->source.is_valid())
                {
                    socket_address = header->source;
                }
                tr_logAddTrace(fmt::format(
                    "PROXY protocol: accepted connection from {} (header: {} bytes)",
                    socket_address.display_name(),
                    header->header_len));
                return true;
            }

            if (result == ParseResult::Incomplete)
            {
                // The stream starts with a header prefix that is not complete
                // yet; it should be finished by the next segment. Wait for it
                // within the budget instead of misjudging the connection.
                if (wait_readable(fd, deadline))
                {
                    continue;
                }
                // The header never arrived in full. A plain peer cannot produce
                // a PROXY prefix, so dropping beats accepting a stream whose
                // first bytes we would not be able to strip.
                tr_logAddTrace("PROXY protocol: incomplete header; dropping connection");
                return false;
            }

            // ParseResult::NotHeader: a plain connection, not relayed by gost.
            return mode_ != TR_PROXY_PROTOCOL_REQUIRE;
        }
    }

    bool Manager::handleUdpDatagram(void const* buf, size_t len, sockaddr* from, socklen_t* fromlen)
    {
        if (mode_ == TR_PROXY_PROTOCOL_OFF)
        {
            return false;
        }

        auto const [result, header] = parse(static_cast<std::byte const*>(buf), len);
        if (result == ParseResult::Complete && header.has_value())
        {
            // gost sends the header as its own datagram, ahead of the payload.
            if (header->source.is_valid())
            {
                if (auto const actual = tr_socket_address::from_sockaddr(from); actual)
                {
                    record(header->source, *actual);
                }
            }
            tr_logAddTrace("PROXY protocol: UDP session header received");
            return true; // drop the header datagram, do not dispatch it
        }

        // Payload datagram: rewrite the sender to the real client if mapped.
        if (auto const actual = tr_socket_address::from_sockaddr(from); actual)
        {
            if (auto const it = actual_to_real_.find(*actual); it != std::end(actual_to_real_))
            {
                auto const real = it->second;
                if (auto const [storage, storage_len] = real.to_sockaddr(); storage_len > 0)
                {
                    std::memcpy(from, &storage, sizeof(storage));
                    *fromlen = storage_len;
                    if (auto const sit = sessions_.find(real); sit != std::end(sessions_))
                    {
                        sit->second.last_seen = std::chrono::steady_clock::now();
                    }
                }
            }
        }
        return false;
    }

    std::optional<tr_socket_address> Manager::rewriteOutbound(sockaddr const* to)
    {
        if (mode_ == TR_PROXY_PROTOCOL_OFF)
        {
            return std::nullopt;
        }

        auto const real = tr_socket_address::from_sockaddr(to);
        if (!real)
        {
            return std::nullopt;
        }

        if (auto const it = sessions_.find(*real); it != std::end(sessions_))
        {
            it->second.last_seen = std::chrono::steady_clock::now();
            return it->second.actual;
        }
        return std::nullopt;
    }

    // --- socket registry (for libdht's sendto hook, which has no session pointer)

    namespace
    {
        std::map<tr_socket_t, Manager*> g_socket_managers;
    } // namespace

    void register_socket(tr_socket_t sockfd, Manager& manager)
    {
        g_socket_managers[sockfd] = &manager;
    }

    void unregister_socket(tr_socket_t sockfd)
    {
        g_socket_managers.erase(sockfd);
    }

    Manager* find_manager(tr_socket_t sockfd) noexcept
    {
        auto const it = g_socket_managers.find(sockfd);
        return it == std::end(g_socket_managers) ? nullptr : it->second;
    }
} // namespace tr::proxy_protocol
