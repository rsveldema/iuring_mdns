#pragma once

#include <memory>
#include <string>
#include <slogger/ILogger.hpp>

#include "mdns/MDNS_Service.hpp"

namespace mdns
{
class INMOS_Service
{
public:
   virtual void start_registration(
        const iuring::IPAddress& ip_address_of_nmos_registration_server,
        std::optional<uint16_t> port_of_registration_server) = 0;

    virtual uint32_t num_self() = 0;
    virtual uint32_t num_devices() = 0;
    virtual uint32_t num_source() = 0;
    virtual uint32_t num_flows() = 0;
    virtual uint32_t num_senders() = 0;
    virtual uint32_t num_receivers() = 0;
};


class MDNS_NMOS_HTTP_Handler : public IMDNS_Handler
{
public:
    MDNS_NMOS_HTTP_Handler(const std::shared_ptr<iuring::IOUringInterface>& network,
            logging::ILogger& logger,
            INMOS_Service& nmos_service,
            iuring::NetworkAdapter& adapter)
    : IMDNS_Handler(network, logger, adapter),
        m_nmos_service(nmos_service)
    {
    }


    MDNS_IsHandled handle_question(const QuestionData& q, IAnswerList& answer) override;
    MDNS_IsHandled handle_reply(const std::vector<ReplyData>& reply) override;

private:
    INMOS_Service& m_nmos_service;

    std::optional<iuring::IPAddress> resolve_dns_request(const name_list_t& name_list);
};

} // namespace mdns