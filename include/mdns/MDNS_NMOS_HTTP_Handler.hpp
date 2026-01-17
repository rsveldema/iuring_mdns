#pragma once

#include <memory>
#include <slogger/ILogger.hpp>
#include <string>

#include "mdns/MDNS_Service.hpp"

namespace mdns
{
class INMOS_Service
{
public:
    virtual ~INMOS_Service() = default;

    virtual void start_registration(
        const iuring::IPAddress& ip_address_of_nmos_registration_server,
        std::optional<uint16_t> port_of_registration_server) = 0;

    virtual size_t num_self() const = 0;
    virtual size_t num_devices() const = 0;
    virtual size_t num_source() const = 0;
    virtual size_t num_flows() const = 0;
    virtual size_t num_senders() const = 0;
    virtual size_t num_receivers() const = 0;
};


class MDNS_NMOS_HTTP_Handler : public IMDNS_Handler
{
public:
    MDNS_NMOS_HTTP_Handler(
        const std::shared_ptr<iuring::IOUringInterface>& network,
        logging::ILogger& logger, INMOS_Service& nmos_service,
        iuring::NetworkAdapter& adapter)
        : IMDNS_Handler(network, logger, adapter)
        , m_nmos_service(nmos_service)
    {
    }


    MDNS_IsHandled handle_question(
        const QuestionData& q, IAnswerList& answer) override;
    MDNS_IsHandled handle_reply(const std::vector<ReplyData>& reply) override;

private:
    INMOS_Service& m_nmos_service;

    std::optional<iuring::IPAddress> resolve_dns_request(
        const name_list_t& name_list);
};

} // namespace mdns