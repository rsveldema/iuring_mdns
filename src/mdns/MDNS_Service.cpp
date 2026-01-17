#include <sstream>

#include <iuring/IPAddress.hpp>

#include <mdns/MDNS_Service.hpp>

#include <Application.hpp>
#include <ptp/PtpService.hpp>


namespace mdns
{
static constexpr uint8_t CACHE_FLASH_SHIFT = 15;

static constexpr const char* _MDNS_MCAST_IPADDR = "224.0.0.251";
static constexpr const char* _MDNS_MCAST_IPADDR6 = "FF02::FB";

iuring::IPAddress MDNS_Service::MDNS_MCAST_IPADDR =
    iuring::IPAddress::parse(_MDNS_MCAST_IPADDR).value();
iuring::IPAddress MDNS_Service::MDNS_MCAST_IPADDR6 =
    iuring::IPAddress::parse(_MDNS_MCAST_IPADDR6).value();


// From the Ravenna documentation:
//
// <vendor node id>._http._tcp.
// <vendor node id>._rtsp._tcp.
// <user defined node name>._http._tcp.
// <user defined node name>._rtsp._tcp.
//
// To enable browsing specifically for RAVENNA services, we additionally
// register "ravenna" sub types with the "vendor node ID":
//
// <vendor node id>._ravenna._sub._http._tcp.
// <vendor node id>._ravenna._sub._rtsp._tcp.
//
//  Note: aneman sends a MDNS query to '_ravenna._sub._http._tcp.local'
//

std::string get_vendor_node_id()
{
    return "fa_node_id";
}

std::string get_vendor_node_name()
{
    return "fanode";
}


void append(iuring::SendPacket& payload, const name_list_t& name)
{
    const auto mdns_name = StringUtils::to_mdns_string(name);
    payload.append(mdns_name);
}


void append_record_PTR(iuring::SendPacket& payload, const name_list_t& name,
    const name_list_t& value, uint16_t& num_answers)
{
    num_answers++;
    const uint32_t ttl_secs = 4500;

    const auto v = StringUtils::to_mdns_string(value);

    append(payload, name);
    payload.append_uint16(static_cast<uint16_t>(DNS_RecordType::PTR));
    payload.append_uint16(
        static_cast<uint16_t>(MDNS_class::IN) | (0 << CACHE_FLASH_SHIFT));
    payload.append_uint32(ttl_secs);
    payload.append_uint16(v.length());
    payload.append(v);
}

void append_record_TXT(iuring::SendPacket& payload, const name_list_t& name,
    const std::string& txt, uint16_t& num_answers)
{
    num_answers++;
    const uint32_t ttl_secs = 4500;

    append(payload, name);
    payload.append_uint16(static_cast<uint16_t>(DNS_RecordType::TXT));
    payload.append_uint16(
        static_cast<uint16_t>(MDNS_class::IN) | (0 << CACHE_FLASH_SHIFT));
    payload.append_uint32(ttl_secs);


    const uint16_t data_length = 1 + txt.length();
    payload.append_uint16(data_length);
    payload.append_byte(txt.length()); // string terminator
    payload.append(txt);
}

void append_record_SRV(iuring::SendPacket& payload, const name_list_t& name,
    const name_list_t& hostname_list, uint16_t& num_answers)
{
    num_answers++;
    const uint32_t ttl_secs = 120;
    const uint16_t priority = 0;
    const uint16_t weight = 0;
    const uint16_t port =
        static_cast<uint16_t>(iuring::SocketPortID::UNENCRYPTED_WEB_PORT);

    append(payload, name);
    payload.append_uint16(static_cast<uint16_t>(DNS_RecordType::SRV));
    payload.append_uint16(
        static_cast<uint16_t>(MDNS_class::IN) | (1 << CACHE_FLASH_SHIFT));
    payload.append_uint32(ttl_secs);

    const auto hostname = StringUtils::to_mdns_string(hostname_list);

    const uint16_t data_length = 6 + hostname.length();
    payload.append_uint16(data_length);
    payload.append_uint16(priority);
    payload.append_uint16(weight);
    payload.append_uint16(port);
    payload.append(hostname);
}

void append_record_A(iuring::SendPacket& payload, const name_list_t& name,
    const in_addr& addr, uint16_t& num_answers)
{
    num_answers++;
    const uint32_t ttl_secs = 120;

    append(payload, name);
    payload.append_uint16(static_cast<uint16_t>(DNS_RecordType::A));
    payload.append_uint16(
        static_cast<uint16_t>(MDNS_class::IN) | (1 << CACHE_FLASH_SHIFT));
    payload.append_uint32(ttl_secs);

    constexpr uint16_t data_length = sizeof(addr.s_addr);
    payload.append_uint16(data_length);
    static_assert(data_length == 4);
    payload.append((const uint8_t*) &addr.s_addr, sizeof(addr.s_addr));
}

class MyAnswerList : public IAnswerList
{
public:
    void append_PTR(const name_list_t& name, const name_list_t& value) override
    {
        append_record_PTR(payload, name, value, num_answers);
    }
    void append_TXT(const name_list_t& name, const std::string& txt) override
    {
        append_record_TXT(payload, name, txt, num_answers);
    }
    void append_SRV(
        const name_list_t& name, const name_list_t& hostname_list) override
    {
        append_record_SRV(payload, name, hostname_list, num_answers);
    }
    void append_A(const name_list_t& name, const in_addr& addr) override
    {
        append_record_A(payload, name, addr, num_answers);
    }

    uint16_t get_num_answers() const
    {
        return num_answers;
    }

    const uint8_t* data() const
    {
        return payload.data();
    }
    size_t size() const
    {
        return payload.size();
    }

private:
    iuring::SendPacket payload;
    uint16_t num_answers = 0;
};

void MDNS_Service::send_reply(const std::vector<QuestionData>& questions,
    const iuring::IPAddress& from_address, transaction_id_t id)
{
    MyAnswerList answerlist;
    for (auto& q : questions)
    {
        bool handled = false;
        for (auto& h : m_handlers)
        {
            if (h->handle_question(q, answerlist) == MDNS_IsHandled::IS_HANDLED)
            {
                handled = true;
                break;
            }
        }

        if (!handled)
        {
            LOG_INFO(get_logger(), "ignoring: {} from {}",
                StringUtils::to_string(q.name_list),
                from_address.to_human_readable_ip_string());
        }
    }

    if (answerlist.get_num_answers() == 0)
    {
        LOG_DEBUG(get_logger(), "mdns query not for us: no answers");
        return;
    }

    LOG_INFO(get_logger(), "REPLYING TO MDNS QUERY!!! ({}:{}) - from {}",
        MDNS_MCAST_IPADDR, m_listen_socket->get_port(),
        from_address.to_human_readable_ip_string());

    const auto dest_addr = iuring::create_sock_addr_in(
        MDNS_MCAST_IPADDR, m_listen_socket->get_port(), get_logger());

    auto wi = get_io()->ackuire_send_workitem(m_listen_socket);

    auto& pkt = wi->get_send_packet();
    MDNS_Header hdr(
        MDNS_Header::MessageType::REPLY, id, answerlist.get_num_answers(), 0);
    pkt.append(hdr);
    pkt.append(answerlist.data(), answerlist.size());

    wi->submit_packet(
        iuring::DatagramSendParameters{ .destination_address = dest_addr,
            .dscp = iuring::dscp_t::BEST_EFFORT,
            .ttl = iuring::timetolive_t::MDNS_TTL },
        [](const iuring::SendResult&) {});
}

const uint8_t* extract_name(const uint8_t* start_of_packet,
    const uint8_t* end_of_packet, std::vector<std::string>& name_list,
    const uint8_t* ptr, logging::ILogger& logger)
{
    const auto size_of_packet = (end_of_packet - start_of_packet);
    constexpr auto mask_11 = 0b11000000;

    while (true)
    {
        // Check bounds before reading length byte
        if (ptr >= end_of_packet)
        {
            LOG_ERROR(logger, "MDNS name extraction: pointer out of bounds");
            return nullptr;
        }
        
        const uint8_t len = *ptr++;
        
        // Length of 0 marks end of name
        if (len == 0)
        {
            break;
        }
        
        // Check we still have room after reading the length byte
        if (ptr >= end_of_packet)
        {
            LOG_ERROR(logger, "MDNS name extraction: unexpected end after length byte");
            return nullptr;
        }

        if ((len & mask_11) == mask_11)
        {
            // Compressed name pointer
            const auto offset_high = len & ~mask_11;
            const auto offset_low = *ptr;
            const auto offset = (offset_high << 8) | offset_low;
            ptr++;

            LOG_DEBUG(logger,
                "len 0x{:x}, offset = {} ({:x} {:x}), pkt size = {}\n", len,
                offset, offset_high, offset_low, size_of_packet);

            if (offset >= size_of_packet)
            {
                LOG_ERROR(logger, "MDNS name extraction: invalid offset {} >= packet size {}", 
                    offset, size_of_packet);
                return nullptr;
            }

            extract_name(start_of_packet, end_of_packet, name_list,
                start_of_packet + offset, logger);
            break;
        }
        else
        {
            // Regular label - check if we have enough bytes
            if (ptr + len > end_of_packet)
            {
                LOG_ERROR(logger, "MDNS name extraction: label length {} exceeds packet boundary", len);
                return nullptr;
            }
            
            std::string s((const char*) ptr, len);

            // fprintf(stderr, "found string[0x{:x}, off 0x%lx]: {}\n", len,
            // (ptr
            // - start_of_packet), s.c_str());

            name_list.push_back(s);
            ptr += len;
        }
    }
    return ptr;
}


void MDNS_Service::handle_query(
    const iuring::ReceivedMessage& data, const MDNS_Header* hdr)
{
    std::vector<QuestionData> questions;

    const auto id = hdr->get_transaction_id();

    const uint8_t* ptr = (const uint8_t*) (hdr + 1);
    assert(ptr < data.end());
    for (int i = 0; i < hdr->get_num_questions(); i++)
    {
        std::vector<std::string> name_list;
        ptr = extract_name(
            data.begin(), data.end(), name_list, ptr, get_logger());
        if (!ptr)
        {
            LOG_ERROR(get_logger(), "malformed mdns packet??");
            return;
        }

        uint16_t type = ntohs(*(uint16_t*) ptr);
        ptr += sizeof(type);

        uint16_t clazz_flags = ntohs(*(uint16_t*) ptr);
        ptr += sizeof(clazz_flags);

        const auto clazz_id =
            static_cast<MDNS_class>(0b0111111111111111 & clazz_flags);
        const auto question_unicast = (0b1000000000000000 & clazz_flags) != 0;

        LOG_DEBUG(get_logger(),
            "XXXXXXXXXXXXXX received MDNS QUESTION[{}]: (type:{:x}, "
            "clazz:{:x}) {}",
            i, type, clazz_flags, StringUtils::to_string(name_list).c_str());


        // name = _services._dns-sd._udp.local
        // type = 0x00ff (ANY)
        // clazz_fl
        questions.push_back(QuestionData{ .name_list = name_list,
            .type = type,
            .clazz = clazz_id,
            .question_unicast = question_unicast });
    }

    run_oneshot_idle_task("send-mdns-reply",
        [this, questions, addr = data.get_source_address(), id](
            realtime::BaseTask&) {
            send_reply(questions, addr, id);
            return realtime::TaskStatus::TASK_OK;
        });
}

void MDNS_Service::handle_reply(
    const iuring::ReceivedMessage& data, const MDNS_Header* hdr)
{
    std::vector<ReplyData> replies;

    const uint8_t* ptr = (const uint8_t*) (hdr + 1);
    assert(ptr < data.end());
    LOG_INFO(get_logger(), "MDNS_HANDLE REPLY: handle {} answers",
        hdr->get_num_answers());
    for (int i = 0; i < hdr->get_num_answers(); i++)
    {
        std::vector<std::string> name_list;
        ptr = extract_name(
            data.begin(), data.end(), name_list, ptr, get_logger());
        if (!ptr)
        {
            LOG_ERROR(get_logger(), "malformed mdns packet??");
            return;
        }


        uint16_t type = ntohs(*(uint16_t*) ptr);
        ptr += sizeof(type);

        uint16_t clazz_flags = ntohs(*(uint16_t*) ptr);
        ptr += sizeof(clazz_flags);

        const auto clazz_id =
            static_cast<MDNS_class>(0b0111111111111111 & clazz_flags);

        uint32_t ttl = ntohl(*(uint32_t*) ptr);
        ptr += sizeof(ttl);

        uint16_t rdlen = ntohs(*(uint16_t*) ptr);
        ptr += sizeof(rdlen);

        const auto* payload_ptr = ptr;
        std::string payload((const char*) ptr, rdlen);
        ptr += rdlen;
        assert(rdlen >= 0);
        assert(rdlen < 32000);

        LOG_DEBUG(get_logger(),
            "XXXXXXXXXXXXXX received MDNS REPLY[{}]: (type:{}/0x{:x}, "
            "clazz:{}, ttl {}) {} <{}>",
            i, type, type, clazz_flags, ttl,
            StringUtils::to_string(name_list).c_str(), payload.c_str());

        std::optional<SRV_payload> SRV;
        std::optional<iuring::IPAddress> A;
        std::optional<name_list_t> PTR;
        std::optional<std::map<std::string, std::string>> TXT;

        switch (type)
        {
        case static_cast<int>(RRType::SRV): {
            const uint8_t* ptr = (const uint8_t*) payload_ptr;
            uint16_t prio = ntohs(*(uint16_t*) ptr);
            ptr += sizeof(prio);

            uint16_t weight = ntohs(*(uint16_t*) ptr);
            ptr += sizeof(weight);

            uint16_t port = ntohs(*(uint16_t*) ptr);
            ptr += sizeof(port);

            name_list_t name_list;
            ptr = extract_name(
                data.begin(), data.end(), name_list, ptr, get_logger());
            if (!ptr)
            {
                LOG_ERROR(get_logger(), "malformed mdns packet??");
                return;
            }

            SRV = SRV_payload{ .prio = prio,
                .weight = weight,
                .port = port,
                .name_list = name_list };
            break;
        }

        case static_cast<int>(RRType::TXT): {
            std::map<std::string, std::string> map;
            const uint8_t* ptr = (const uint8_t*) payload_ptr;
            const uint8_t* end = ptr + rdlen;

            while (ptr < end)
            {
                uint8_t len = *ptr;
                if (len == 0)
                {
                    break;
                }
                ptr++;
                std::string s((const char*) ptr, len);
                if (const auto eq_sign = s.find('=');
                    eq_sign != std::string::npos)
                {
                    const auto k = s.substr(0, eq_sign);
                    const auto v = s.substr(eq_sign + 1);
                    map[k] = v;
                }
                else
                {
                    map[s] = "";
                }
                ptr += len;
            }

            TXT = map;
            break;
        }

        case static_cast<int>(RRType::A): {
            assert(payload.size() == 4);
            in_addr sa;
            memcpy(&sa, payload.data(), payload.size());
            iuring::IPAddress ip(sa, iuring::SocketPortID::UNKNOWN);
            A = ip;
            break;
        }

        case static_cast<int>(RRType::AAAA): {
            assert(payload.size() == 16);
            in6_addr sa6;
            memcpy(&sa6, payload.data(), payload.size());
            iuring::IPAddress ip(sa6, iuring::SocketPortID::UNKNOWN);
            A = ip;
            break;
        }

        case static_cast<int>(RRType::PTR): {
            const uint8_t* ptr = (const uint8_t*) payload_ptr;
            name_list_t name_list;
            ptr = extract_name(
                data.begin(), data.end(), name_list, ptr, get_logger());
            if (!ptr)
            {
                LOG_ERROR(get_logger(), "malformed mdns packet??");
                return;
            }

            PTR = name_list;
            break;
        }


        default:
            break;
        }

        replies.push_back(
            ReplyData{ name_list, type, clazz_id, payload, SRV, A, PTR, TXT });
    }

    bool handled = false;
    for (auto& h : m_handlers)
    {
        if (h->handle_reply(replies) == MDNS_IsHandled::IS_HANDLED)
        {
            handled = true;
            break;
        }
    }

    if (!handled)
    {
        LOG_INFO(get_logger(), "ignoring: {}", StringUtils::to_string(replies));
    }
}


void MDNS_Service::process_event(const iuring::ReceivedMessage& data)
{
    if (sizeof(MDNS_Header) > data.get_size())
    {
        LOG_ERROR(get_logger(),
            "ignoring request, packet too small for mdns header ({} bytes)",
            data.get_size());
        return;
    }

    auto* ptr = data.begin();
    auto* hdr = (MDNS_Header*) ptr;

    switch (hdr->get_message_type())
    {
    case MDNS_Header::MessageType::QUERY:
        handle_query(data, hdr);
        break;
    case MDNS_Header::MessageType::REPLY:
        handle_reply(data, hdr);
        break;
    }
}

[[nodiscard]] error::Error MDNS_Service::init()
{
    const auto port = iuring::SocketPortID::MDNS_PORT;

    m_listen_socket = m_socket_factory.create_impl(iuring::SocketType::IPV4_UDP,
        port, get_logger(), iuring::SocketKind::MULTICAST_PACKET_SOCKET);

    const auto interface_ip_opt = get_adapter().get_interface_ip4();
    assert(interface_ip_opt.has_value());
    const auto interface_ip = interface_ip_opt.value();

    m_listen_socket->join_multicast_group(MDNS_MCAST_IPADDR, interface_ip);
    if (!m_listen_socket)
    {
        return error::Error::FAILED_TO_CREATE_SOCKET;
    }

    LOG_INFO(get_logger(), "MDNS: listening on port {}, interface {}",
        static_cast<int>(port), interface_ip);

    get_io()->submit_recv(
        m_listen_socket, [this](const iuring::ReceivedMessage& data) {
            process_event(data);
            return iuring::ReceivePostAction::RE_SUBMIT;
        });
    return error::Error::OK;
}

} // namespace mdns