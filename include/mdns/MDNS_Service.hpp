#pragma once

#include <format>
#include <map>
#include <string>

#include <iuring/IOUringInterface.hpp>
#include <iuring/ISocketFactory.hpp>

#include <slogger/ILogger.hpp>

#include <urtsched/RealtimeKernel.hpp>
#include <urtsched/Service.hpp>

#include "MDNS_Header.hpp"

#include "IMDNS_Handler.hpp"

namespace mdns
{
class MDNS_Service : public service::Service
{
public:
    static iuring::IPAddress MDNS_MCAST_IPADDR;
    static iuring::IPAddress MDNS_MCAST_IPADDR6;

    MDNS_Service(const std::shared_ptr<realtime::RealtimeKernel>& rt_kernel,
        const std::shared_ptr<iuring::IOUringInterface>& network,
        logging::ILogger& logger, iuring::NetworkAdapter& adapter,
        iuring::ISocketFactory& socket_factory)
        : service::Service(rt_kernel, logger)
        , m_socket_factory(socket_factory)
        , m_adapter(adapter)
        , m_network(network)
    {
    }

    std::shared_ptr<iuring::IOUringInterface>& get_io()
    {
        return m_network;
    }

    [[nodiscard]] error::Error init();

    error::Error finish() override
    {
        return error::Error::OK;
    }

    void add_handler(const std::shared_ptr<IMDNS_Handler>& handler)
    {
        m_handlers.push_back(handler);
    }

private:
    iuring::ISocketFactory& m_socket_factory;
    iuring::NetworkAdapter& m_adapter;
    std::vector<std::shared_ptr<IMDNS_Handler>> m_handlers;
    std::shared_ptr<iuring::ISocket> m_listen_socket;
    std::shared_ptr<iuring::IOUringInterface> m_network;

    iuring::NetworkAdapter& get_adapter()
    {
        return m_adapter;
    }

    void send_reply(const std::vector<QuestionData>& questions,
        const iuring::IPAddress& from_address, transaction_id_t id);

    void handle_query(
        const iuring::ReceivedMessage& data, const MDNS_Header* hdr);
    void handle_reply(
        const iuring::ReceivedMessage& data, const MDNS_Header* hdr);

    void process_event(const iuring::ReceivedMessage& data);
};

std::string get_vendor_node_id();
std::string get_vendor_node_name();

namespace
{

    [[maybe_unused]] name_list_t create_list(const std::string& a)
    {
        return name_list_t{ a };
    }

    [[maybe_unused]] name_list_t create_list(
        const std::string& a, const std::string& b)
    {
        return name_list_t{ a, b };
    }

    [[maybe_unused]] name_list_t create_list(
        const std::string& a, const std::string& b, const std::string& c)
    {
        return name_list_t{ a, b, c };
    }

    [[maybe_unused]] name_list_t create_list(const std::string& a,
        const std::string& b, const std::string& c, const std::string& d)
    {
        return name_list_t{ a, b, c, d };
    }

    [[maybe_unused]] name_list_t create_list(const std::string& a,
        const std::string& b, const std::string& c, const std::string& d,
        const std::string& e)
    {
        return name_list_t{ a, b, c, d, e };
    }
} // namespace
} // namespace mdns


template <> struct std::formatter<mdns::RRType>
{
    constexpr auto parse(std::format_parse_context& ctx)
    {
        return ctx.begin();
    }


    auto format(mdns::RRType c, std::format_context& ctx) const
    {
        std::string name;
        switch (c)
        {
        case mdns::RRType::A:
            name = "A";
            break;
        case mdns::RRType::NS:
            name = "NS";
            break;
        case mdns::RRType::MD:
            name = "MD";
            break;
        case mdns::RRType::CNAME:
            name = "CNAME";
            break;
        case mdns::RRType::WKKS:
            name = "WKKS";
            break;
        case mdns::RRType::PTR:
            name = "PTR";
            break;
        case mdns::RRType::TXT:
            name = "TXT";
            break;
        case mdns::RRType::SRV:
            name = "SRV";
            break;
        default:
            name = "Unknown";
            break;
        }
        return std::format_to(ctx.out(), "{}", name);
    }
};
