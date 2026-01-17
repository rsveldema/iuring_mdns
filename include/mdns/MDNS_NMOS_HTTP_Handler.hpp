#pragma once

#include <memory>
#include <string>
#include <slogger/ILogger.hpp>

#include "mdns/MDNS_Service.hpp"
#include "nmos/NMOS_Service.hpp"

namespace mdns
{
class MDNS_NMOS_HTTP_Handler : public IMDNS_Handler
{
public:
    MDNS_NMOS_HTTP_Handler(const std::shared_ptr<iuring::IOUringInterface>& network,
            logging::ILogger& logger,
            NMOS::NMOS_Service& nmos_service,
            iuring::NetworkAdapter& adapter)
    : IMDNS_Handler(network, logger, adapter),
        m_nmos_service(nmos_service)
    {
    }


    MDNS_IsHandled handle_question(const QuestionData& q, IAnswerList& answer) override;
    MDNS_IsHandled handle_reply(const std::vector<ReplyData>& reply) override;

private:
    NMOS::NMOS_Service& m_nmos_service;


    std::optional<iuring::IPAddress> resolve_dns_request(const name_list_t& name_list);
};

} // namespace mdns