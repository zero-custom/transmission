// This file Copyright (C) 2026.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.

#include <array>
#include <chrono> // std::chrono literals
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <fcntl.h> // fcntl(), F_SETFL, O_NONBLOCK
#include <sys/socket.h> // socketpair()
#include <thread> // std::thread
#include <unistd.h> // close(), read(), write()
#endif

#include <libtransmission/net.h>
#include <libtransmission/proxy-protocol.h>
#include <libtransmission/quark.h>
#include <libtransmission/session.h> // tr_session::Settings
#include <libtransmission/variant.h>

#include "test-fixtures.h"

using namespace std::literals;

namespace
{
    // Reuse the parser's own signature bytes so these tests can never drift
    // from what parse() matches against.
    using tr::proxy_protocol::V2Signature;

    void appendPortBE(std::vector<std::byte>& out, uint16_t port)
    {
        out.push_back(std::byte{ static_cast<uint8_t>(port >> 8U) });
        out.push_back(std::byte{ static_cast<uint8_t>(port & 0xFFU) });
    }

    // Build a v2 header: signature + version/command + family + length + address block.
    std::vector<std::byte> makeV2Header(uint8_t ver_cmd, uint8_t fam, std::byte const* addr_block, size_t addr_len)
    {
        auto out = std::vector<std::byte>{};
        out.reserve(16U + addr_len);
        out.insert(std::end(out), std::begin(V2Signature), std::end(V2Signature));
        out.push_back(std::byte{ ver_cmd });
        out.push_back(std::byte{ fam });
        appendPortBE(out, static_cast<uint16_t>(addr_len));
        if (addr_len > 0U)
        {
            out.insert(std::end(out), addr_block, addr_block + addr_len);
        }
        return out;
    }

    std::vector<std::byte> makeV2Inet(
        std::string_view src_ip,
        uint16_t src_port,
        std::string_view dst_ip,
        uint16_t dst_port)
    {
        auto block = std::vector<std::byte>{};
        block.reserve(12U);
        auto const src = tr_address::from_string(src_ip);
        auto const dst = tr_address::from_string(dst_ip);
        auto src_addr = src.value_or(tr_address::any(TR_AF_INET));
        auto dst_addr = dst.value_or(tr_address::any(TR_AF_INET));
        auto out = std::back_inserter(block);
        out = tr_socket_address::to_compact(out, src_addr, tr_port::from_host(src_port));
        out = tr_socket_address::to_compact(out, dst_addr, tr_port::from_host(dst_port));
        return makeV2Header(0x20, 0x11, std::data(block), std::size(block));
    }

    std::vector<std::byte> toBytes(std::string_view s)
    {
        auto out = std::vector<std::byte>{};
        out.reserve(std::size(s));
        for (auto const c : s)
        {
            out.push_back(std::byte{ static_cast<uint8_t>(c) });
        }
        return out;
    }

    std::vector<std::byte> v1Header(std::string_view src_ip, uint16_t src_port, std::string_view dst_ip, uint16_t dst_port)
    {
        auto line = std::string{ "PROXY TCP4 " };
        line += src_ip;
        line += ' ';
        line += dst_ip;
        line += ' ';
        line += std::to_string(src_port);
        line += ' ';
        line += std::to_string(dst_port);
        line += "\r\n";
        return toBytes(line);
    }

#ifdef _WIN32
    char constexpr SocketTestUnsupported = 0;
#else
    // Create a connected pair of non-blocking sockets.
    void makeSocketPair(int fds[2])
    {
        ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
        for (auto const fd : { fds[0], fds[1] })
        {
            (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        }
    }
#endif
} // namespace

TEST(ProxyProtocolParse, v1Tcp4)
{
    auto const data = v1Header("1.2.3.4", 1234, "5.6.7.8", 5678);

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ("1.2.3.4", header->source.address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), header->source.port());
    EXPECT_EQ(std::size(data), header->header_len);
}

TEST(ProxyProtocolParse, v1Tcp6)
{
    auto const data = toBytes("PROXY TCP6 2001:db8::1 2001:db8::2 1234 5678\r\n");

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ("2001:db8::1", header->source.address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), header->source.port());
    EXPECT_EQ(std::size(data), header->header_len);
}

TEST(ProxyProtocolParse, v1Unknown)
{
    auto const data = toBytes("PROXY UNKNOWN\r\n");

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(header.has_value());
    EXPECT_FALSE(header->source.is_valid());
    EXPECT_EQ(std::size(data), header->header_len);
}

TEST(ProxyProtocolParse, v1Incomplete)
{
    auto const data = toBytes("PROXY TCP4 1.2.3.4 5.6.7.8 12"); // no CRLF yet

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Incomplete, result);
    EXPECT_FALSE(header.has_value());
}

TEST(ProxyProtocolParse, v1MalformedLine)
{
    // "PROXY " prefix with a CRLF-terminated line that isn't a valid header
    auto const data = toBytes("PROXY NOTAPROTOCOL\r\n");

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::NotHeader, result);
    EXPECT_FALSE(header.has_value());
}

TEST(ProxyProtocolParse, v1TooLong)
{
    // v1 lines must be at most 107 bytes including the CRLF
    auto data = std::vector<std::byte>{};
    auto line = std::string{ "PROXY TCP4 " };
    for (size_t i = 0; i < 30; ++i) // >> 107 bytes total
    {
        line += "1.2.3.4 5.6.7.8 1234 5678 ";
    }
    line += "\r\n";
    data = toBytes(line);

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::NotHeader, result);
    EXPECT_FALSE(header.has_value());
}

TEST(ProxyProtocolParse, v1PartialPrefix)
{
    auto const data = toBytes("PROX");

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Incomplete, result);
    EXPECT_FALSE(header.has_value());
}

TEST(ProxyProtocolParse, v1TrailingPayload)
{
    auto header = v1Header("1.2.3.4", 1234, "5.6.7.8", 5678);
    auto payload = toBytes("\x13"
                           "BitTorrent protocol");
    header.insert(std::end(header), std::begin(payload), std::end(payload));

    auto const [result, parsed] = tr::proxy_protocol::parse(std::data(header), std::size(header));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ("1.2.3.4", parsed->source.address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), parsed->source.port());
    // only the header is consumed; the payload stays
    EXPECT_EQ(std::size(v1Header("1.2.3.4", 1234, "5.6.7.8", 5678)), parsed->header_len);
}

TEST(ProxyProtocolParse, v2Inet)
{
    auto const data = makeV2Inet("1.2.3.4", 1234, "5.6.7.8", 5678);

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ("1.2.3.4", header->source.address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), header->source.port());
    EXPECT_EQ(28U, header->header_len); // 16-byte fixed header + 12-byte addr block
}

TEST(ProxyProtocolParse, v2Inet6)
{
    auto block = std::vector<std::byte>{};
    block.reserve(36U);
    auto const src = tr_address::from_string("2001:db8::1");
    auto const dst = tr_address::from_string("2001:db8::2");
    auto out = std::back_inserter(block);
    out = tr_socket_address::to_compact(out, *src, tr_port::from_host(1234));
    out = tr_socket_address::to_compact(out, *dst, tr_port::from_host(5678));
    auto const data6 = makeV2Header(0x20, 0x21, std::data(block), std::size(block));

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data6), std::size(data6));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ("2001:db8::1", header->source.address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), header->source.port());
    EXPECT_EQ(52U, header->header_len); // 16-byte fixed header + 36-byte addr block
}

TEST(ProxyProtocolParse, v2Local)
{
    // LOCAL command (0x21): carries no address info
    auto const data = makeV2Header(0x21, 0x00, nullptr, 0);

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(header.has_value());
    EXPECT_FALSE(header->source.is_valid());
    EXPECT_EQ(16U, header->header_len);
}

TEST(ProxyProtocolParse, v2Unspec)
{
    // PROXY command with UNSPEC family (0x00): TLVs only, no address
    auto const data = makeV2Header(0x20, 0x00, nullptr, 0);

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(header.has_value());
    EXPECT_FALSE(header->source.is_valid());
    EXPECT_EQ(16U, header->header_len);
}

TEST(ProxyProtocolParse, v2Incomplete)
{
    // signature + partial fixed header
    auto data = toBytes("\r\n\r\n\x00\r\nQUIT\n\x20\x11\x00");
    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Incomplete, result);
    EXPECT_FALSE(header.has_value());

    // claims a 12-byte address block but only provides a few bytes
    auto data2 = makeV2Inet("1.2.3.4", 1234, "5.6.7.8", 5678);
    data2.resize(20U);
    auto const [result2, header2] = tr::proxy_protocol::parse(std::data(data2), std::size(data2));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Incomplete, result2);
    EXPECT_FALSE(header2.has_value());
}

TEST(ProxyProtocolParse, v2TrailingPayload)
{
    auto data = makeV2Inet("1.2.3.4", 1234, "5.6.7.8", 5678);
    auto payload = toBytes("\x13"
                           "BitTorrent protocol");
    data.insert(std::end(data), std::begin(payload), std::end(payload));

    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::Complete, result);
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(28U, header->header_len);
}

TEST(ProxyProtocolParse, notAHeader)
{
    auto const data = toBytes("\x13"
                              "BitTorrent protocol");
    auto const [result, header] = tr::proxy_protocol::parse(std::data(data), std::size(data));
    EXPECT_EQ(tr::proxy_protocol::ParseResult::NotHeader, result);
    EXPECT_FALSE(header.has_value());
}

TEST(ProxyProtocolManager, offModeIsNoop)
{
    auto manager = tr::proxy_protocol::Manager{}; // default: TR_PROXY_PROTOCOL_OFF
    auto addr = tr_socket_address{ tr_address::from_string("1.2.3.4").value(), tr_port::from_host(1234) };

    // even a plausible header datagram must not be consumed in off mode
    auto header = makeV2Inet("1.2.3.4", 1234, "5.6.7.8", 5678);
    auto from = sockaddr_storage{};
    auto fromlen = socklen_t{ sizeof(from) };
    EXPECT_FALSE(manager.handleUdpDatagram(std::data(header), std::size(header), reinterpret_cast<sockaddr*>(&from), &fromlen));

    auto const addr_ss = tr_socket_address::to_sockaddr(addr).first;
    EXPECT_FALSE(manager.rewriteOutbound(reinterpret_cast<sockaddr const*>(&addr_ss)));
}

TEST(ProxyProtocolManager, udpHeaderRecordsMappingAndRewrites)
{
    auto manager = tr::proxy_protocol::Manager{ TR_PROXY_PROTOCOL_ALLOW };

    // inbound header datagram from the gost relay (127.0.0.1:5555) claims client 1.2.3.4:1234
    auto header = makeV2Inet("1.2.3.4", 1234, "5.6.7.8", 5678);
    auto from = sockaddr_storage{};
    auto fromlen = socklen_t{ sizeof(from) };
    auto* const from_sa = reinterpret_cast<sockaddr*>(&from);
    auto const actual = tr_socket_address{ tr_address::from_string("127.0.0.1").value(), tr_port::from_host(5555) };
    auto [actual_ss, actual_len] = tr_socket_address::to_sockaddr(actual);
    std::memcpy(from_sa, &actual_ss, sizeof(actual_ss));
    fromlen = actual_len;

    EXPECT_TRUE(manager.handleUdpDatagram(std::data(header), std::size(header), from_sa, &fromlen));

    // outbound rewrite: a reply to the real client must go back through the relay
    auto reply_to = tr_socket_address{ tr_address::from_string("1.2.3.4").value(), tr_port::from_host(1234) };
    auto const reply_to_ss = tr_socket_address::to_sockaddr(reply_to).first;
    auto const rewritten_out = manager.rewriteOutbound(reinterpret_cast<sockaddr const*>(&reply_to_ss));
    ASSERT_TRUE(rewritten_out.has_value());
    EXPECT_EQ(actual, *rewritten_out);

    // inbound rewrite: a payload datagram from the relay is attributed to the real client
    auto payload = toBytes("d1:ad2:id20:01234567890123456789e");
    from = sockaddr_storage{};
    std::memcpy(from_sa, &actual_ss, sizeof(actual_ss));
    fromlen = actual_len;
    EXPECT_FALSE(manager.handleUdpDatagram(std::data(payload), std::size(payload), from_sa, &fromlen));
    auto const rewritten = tr_socket_address::from_sockaddr(from_sa);
    ASSERT_TRUE(rewritten.has_value());
    EXPECT_EQ("1.2.3.4", rewritten->address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), rewritten->port());
}

TEST(ProxyProtocolManager, socketRegistry)
{
    auto manager = tr::proxy_protocol::Manager{};
    auto const fake_sockfd = tr_socket_t{ 12345 };

    EXPECT_EQ(nullptr, tr::proxy_protocol::find_manager(fake_sockfd));
    tr::proxy_protocol::register_socket(fake_sockfd, manager);
    EXPECT_EQ(&manager, tr::proxy_protocol::find_manager(fake_sockfd));
    tr::proxy_protocol::unregister_socket(fake_sockfd);
    EXPECT_EQ(nullptr, tr::proxy_protocol::find_manager(fake_sockfd));
}

namespace tr::test
{
    // Friend of tr::proxy_protocol::Manager, so the helpers below can drive the
    // UDP session mapping and clock directly instead of sleeping 15 minutes.
    // Private access must stay in this class: gtest's TEST_F bodies run in a
    // *derived* class, and friendship is not inherited.
    class ProxyProtocolTest : public ::testing::Test
    {
    protected:
        tr::proxy_protocol::Manager manager_{ TR_PROXY_PROTOCOL_ALLOW };

        static tr_socket_address addr(std::string_view host, uint16_t port)
        {
            return tr_socket_address{ tr_address::from_string(host).value(), tr_port::from_host(port) };
        }

        static sockaddr_storage sockaddr_of(tr_socket_address const& a)
        {
            return tr_socket_address::to_sockaddr(a).first;
        }

        static sockaddr* as_sockaddr(sockaddr_storage& storage)
        {
            return reinterpret_cast<sockaddr*>(&storage);
        }

        static sockaddr const* as_sockaddr(sockaddr_storage const& storage)
        {
            return reinterpret_cast<sockaddr const*>(&storage);
        }

        // Dispatch a payload datagram supposedly sent by `from`; returns whether
        // handleUdpDatagram consumed it (false = it was dispatched normally) and
        // rewrites `from` in place when the source address is mapped.
        bool send_payload_from(tr_socket_address const& from, sockaddr_storage& from_out)
        {
            auto payload = toBytes("d1:ad2:id20:01234567890123456789e");
            from_out = sockaddr_of(from);
            auto fromlen = socklen_t{ sizeof(from_out) };
            return manager_.handleUdpDatagram(std::data(payload), std::size(payload), as_sockaddr(from_out), &fromlen);
        }

        void record(tr_socket_address const& real, tr_socket_address const& actual)
        {
            manager_.record(real, actual);
        }

        // Mark the session for `real` as idle past the 15-minute cutoff.
        void expire_session(tr_socket_address const& real)
        {
            manager_.sessions_.at(real).last_seen -= std::chrono::minutes{ 16 };
        }

        void prune()
        {
            manager_.prune(std::chrono::steady_clock::now());
        }

        [[nodiscard]] size_t session_count() const
        {
            return manager_.sessions_.size();
        }

        [[nodiscard]] size_t reverse_index_count() const
        {
            return manager_.actual_to_real_.size();
        }
    };

    TEST_F(ProxyProtocolTest, rebindRealCleansStaleReverseIndex)
    {
        auto const real = addr("1.2.3.4", 1234);
        auto const actual1 = addr("127.0.0.1", 5555);
        auto const actual2 = addr("127.0.0.1", 6666);

        record(real, actual1);
        record(real, actual2); // the gost session (source port) changed

        // the stale reverse entry for actual1 is gone: a payload datagram from
        // actual1 must no longer be attributed to `real`
        auto from = sockaddr_storage{};
        EXPECT_FALSE(this->send_payload_from(actual1, from));
        EXPECT_EQ(actual1, *tr_socket_address::from_sockaddr(as_sockaddr(from)));

        // actual2 still rewrites to the real client
        EXPECT_FALSE(this->send_payload_from(actual2, from));
        EXPECT_EQ(real, *tr_socket_address::from_sockaddr(as_sockaddr(from)));

        // outbound replies to the real client still go back through actual2
        auto const to = sockaddr_of(real);
        auto const rewritten = manager_.rewriteOutbound(as_sockaddr(to));
        ASSERT_TRUE(rewritten.has_value());
        EXPECT_EQ(actual2, *rewritten);

        // both indices hold exactly one session
        EXPECT_EQ(1U, session_count());
        EXPECT_EQ(1U, reverse_index_count());
    }

    TEST_F(ProxyProtocolTest, rebindActualDropsOldForwardEntry)
    {
        auto const real1 = addr("1.2.3.4", 1234);
        auto const real2 = addr("5.6.7.8", 5678);
        auto const actual = addr("127.0.0.1", 5555);

        record(real1, actual);
        record(real2, actual); // the relay session now belongs to real2

        // real1's session is gone: outbound replies to it are sent as-is
        auto const to1 = sockaddr_of(real1);
        EXPECT_FALSE(manager_.rewriteOutbound(as_sockaddr(to1)).has_value());

        // real2 maps to the relay, and inbound traffic is attributed to real2
        auto const to2 = sockaddr_of(real2);
        auto const rewritten = manager_.rewriteOutbound(as_sockaddr(to2));
        ASSERT_TRUE(rewritten.has_value());
        EXPECT_EQ(actual, *rewritten);

        auto from = sockaddr_storage{};
        EXPECT_FALSE(this->send_payload_from(actual, from));
        EXPECT_EQ(real2, *tr_socket_address::from_sockaddr(as_sockaddr(from)));

        EXPECT_EQ(1U, session_count());
        EXPECT_EQ(1U, reverse_index_count());
    }

    TEST_F(ProxyProtocolTest, pruneRemovesIdleSessionsFromBothIndices)
    {
        auto const real1 = addr("1.2.3.4", 1234);
        auto const actual1 = addr("127.0.0.1", 5555);
        auto const real2 = addr("5.6.7.8", 5678);
        auto const actual2 = addr("127.0.0.1", 6666);

        record(real1, actual1);
        record(real2, actual2);

        // real1's session has been idle past the 15-minute cutoff
        expire_session(real1);
        prune();

        auto const to1 = sockaddr_of(real1);
        EXPECT_FALSE(manager_.rewriteOutbound(as_sockaddr(to1)).has_value());

        auto const to2 = sockaddr_of(real2);
        auto const rewritten = manager_.rewriteOutbound(as_sockaddr(to2));
        ASSERT_TRUE(rewritten.has_value());
        EXPECT_EQ(actual2, *rewritten);

        EXPECT_EQ(1U, session_count());
        EXPECT_EQ(1U, reverse_index_count());
    }
} // namespace tr::test

#ifdef _WIN32
TEST(ProxyProtocolManager, DISABLED_tcpAcceptedConsumesHeader) {}
TEST(ProxyProtocolManager, DISABLED_requireTcpNoHeader) {}
TEST(ProxyProtocolManager, DISABLED_allowTcpNoHeader) {}
#else
TEST(ProxyProtocolManager, tcpAcceptedConsumesHeader)
{
    auto fds = std::array<int, 2>{};
    makeSocketPair(std::data(fds));

    auto header = v1Header("1.2.3.4", 1234, "5.6.7.8", 5678);
    auto payload = toBytes("\x13"
                           "BitTorrent protocol");
    header.insert(std::end(header), std::begin(payload), std::end(payload));
    (void)write(fds[1], std::data(header), std::size(header));

    auto manager = tr::proxy_protocol::Manager{ TR_PROXY_PROTOCOL_REQUIRE };
    auto peer_addr = tr_socket_address{ tr_address::from_string("172.16.0.9").value(), tr_port::from_host(7) };
    EXPECT_TRUE(manager.handleTcpAccepted(fds[0], peer_addr));
    EXPECT_EQ("1.2.3.4", peer_addr.address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), peer_addr.port());

    // the payload is still in the stream; the header is gone
    auto rest = std::vector<std::byte>(payload.size(), std::byte{ 0 });
    auto const n_read = read(fds[0], std::data(rest), std::size(rest));
    EXPECT_EQ(std::size(payload), static_cast<size_t>(n_read));
    EXPECT_EQ(payload, rest);

    (void)close(fds[0]);
    (void)close(fds[1]);
}

TEST(ProxyProtocolManager, requireTcpNoHeader)
{
    auto fds = std::array<int, 2>{};
    makeSocketPair(std::data(fds));

    auto payload = toBytes("\x13"
                           "BitTorrent protocol");
    (void)write(fds[1], std::data(payload), std::size(payload));

    auto manager = tr::proxy_protocol::Manager{ TR_PROXY_PROTOCOL_REQUIRE };
    auto peer_addr = tr_socket_address{ tr_address::from_string("172.16.0.9").value(), tr_port::from_host(7) };
    EXPECT_FALSE(manager.handleTcpAccepted(fds[0], peer_addr));

    (void)close(fds[0]);
    (void)close(fds[1]);
}

TEST(ProxyProtocolManager, allowTcpNoHeader)
{
    auto fds = std::array<int, 2>{};
    makeSocketPair(std::data(fds));

    auto payload = toBytes("\x13"
                           "BitTorrent protocol");
    (void)write(fds[1], std::data(payload), std::size(payload));

    auto manager = tr::proxy_protocol::Manager{ TR_PROXY_PROTOCOL_ALLOW };
    auto peer_addr = tr_socket_address{ tr_address::from_string("172.16.0.9").value(), tr_port::from_host(7) };
    EXPECT_TRUE(manager.handleTcpAccepted(fds[0], peer_addr));
    EXPECT_EQ("172.16.0.9", peer_addr.address().display_name());
    EXPECT_EQ(tr_port::from_host(7), peer_addr.port());

    (void)close(fds[0]);
    (void)close(fds[1]);
}

TEST(ProxyProtocolManager, requireTcpWaitsForSplitHeader)
{
    auto fds = std::array<int, 2>{};
    makeSocketPair(std::data(fds));

    // the v1 header arrives in two segments: "PROXY TCP4 1.2.3.4 5.6.7.8 12"
    // followed shortly by "34 5678\r\n"
    auto const first = toBytes("PROXY TCP4 1.2.3.4 5.6.7.8 12");
    auto const second = toBytes("34 5678\r\n");
    (void)write(fds[1], std::data(first), std::size(first));

    auto manager = tr::proxy_protocol::Manager{ TR_PROXY_PROTOCOL_REQUIRE };
    auto peer_addr = tr_socket_address{ tr_address::from_string("172.16.0.9").value(), tr_port::from_host(7) };

    // the rest of the header arrives while handleTcpAccepted is waiting for it
    auto writer = std::thread([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds{ 30 });
        (void)write(fds[1], std::data(second), std::size(second));
    });
    EXPECT_TRUE(manager.handleTcpAccepted(fds[0], peer_addr));
    writer.join();

    EXPECT_EQ("1.2.3.4", peer_addr.address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), peer_addr.port());

    (void)close(fds[0]);
    (void)close(fds[1]);
}

TEST(ProxyProtocolManager, requireTcpWaitsForDelayedHeader)
{
    auto fds = std::array<int, 2>{};
    makeSocketPair(std::data(fds));

    auto manager = tr::proxy_protocol::Manager{ TR_PROXY_PROTOCOL_REQUIRE };
    auto peer_addr = tr_socket_address{ tr_address::from_string("172.16.0.9").value(), tr_port::from_host(7) };

    // no data is buffered yet when accept() fires (the accept-vs-write race);
    // the header arrives while handleTcpAccepted waits for it
    auto header = v1Header("1.2.3.4", 1234, "5.6.7.8", 5678);
    auto writer = std::thread([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds{ 30 });
        (void)write(fds[1], std::data(header), std::size(header));
    });
    EXPECT_TRUE(manager.handleTcpAccepted(fds[0], peer_addr));
    writer.join();

    EXPECT_EQ("1.2.3.4", peer_addr.address().display_name());
    EXPECT_EQ(tr_port::from_host(1234), peer_addr.port());

    (void)close(fds[0]);
    (void)close(fds[1]);
}

TEST(ProxyProtocolManager, requireTcpNoDataIsDropped)
{
    auto fds = std::array<int, 2>{};
    makeSocketPair(std::data(fds));

    auto manager = tr::proxy_protocol::Manager{ TR_PROXY_PROTOCOL_REQUIRE };
    auto peer_addr = tr_socket_address{ tr_address::from_string("172.16.0.9").value(), tr_port::from_host(7) };
    EXPECT_FALSE(manager.handleTcpAccepted(fds[0], peer_addr));

    (void)close(fds[0]);
    (void)close(fds[1]);
}

TEST(ProxyProtocolManager, allowTcpPartialHeaderIsNotAcceptedCorrupted)
{
    auto fds = std::array<int, 2>{};
    makeSocketPair(std::data(fds));

    // a header prefix that never completes must not be accepted as a plain
    // connection: its first bytes could not be stripped from the stream
    auto const prefix = toBytes("PROXY TCP4 1.2.3.4 ");
    (void)write(fds[1], std::data(prefix), std::size(prefix));

    auto manager = tr::proxy_protocol::Manager{ TR_PROXY_PROTOCOL_ALLOW };
    auto peer_addr = tr_socket_address{ tr_address::from_string("172.16.0.9").value(), tr_port::from_host(7) };
    EXPECT_FALSE(manager.handleTcpAccepted(fds[0], peer_addr));

    (void)close(fds[0]);
    (void)close(fds[1]);
}
#endif

TEST(SettingsProxyProtocol, canLoadMode)
{
    static auto constexpr Key = TR_KEY_proxy_protocol;
    static auto constexpr ExpectedValue = TR_PROXY_PROTOCOL_REQUIRE;

    auto settings = std::make_unique<tr_session::Settings>();
    ASSERT_NE(ExpectedValue, settings->proxy_protocol);

    auto map = tr_variant::Map{ 1U };
    map.try_emplace(Key, ExpectedValue);
    settings->load(tr_variant{ std::move(map) });
    EXPECT_EQ(ExpectedValue, settings->proxy_protocol);

    settings = std::make_unique<tr_session::Settings>();
    map = tr_variant::Map{ 1U };
    map.try_emplace(Key, "require"sv);
    settings->load(tr_variant{ std::move(map) });
    EXPECT_EQ(ExpectedValue, settings->proxy_protocol);
}

TEST(SettingsProxyProtocol, canSaveMode)
{
    static auto constexpr Key = TR_KEY_proxy_protocol;
    static auto constexpr SourceValue = TR_PROXY_PROTOCOL_REQUIRE;
    static auto constexpr ExpectedValue = "require"sv;

    auto settings = tr_session::Settings{};
    EXPECT_NE(SourceValue, settings.proxy_protocol);
    settings.proxy_protocol = SourceValue;

    auto const map = settings.save();
    auto const val = map.value_if<std::string_view>(Key);
    ASSERT_TRUE(val);
    EXPECT_EQ(ExpectedValue, *val);
}
