#include <expected>

#include <slogger/ILogger.hpp>

#include "mdns/MDNS_NMOS_HTTP_Handler.hpp"
#include "mdns/MDNS_Service.hpp"

namespace mdns
{
std::string toString_8bit(uint8_t v)
{
    return std::format("{}", v);
}

MDNS_IsHandled MDNS_NMOS_HTTP_Handler::handle_question(
    const QuestionData& q, [[maybe_unused]] IAnswerList& answer)
{
    /*
    _nmos-node._tcp: A logical host which advertises a Node API.
    _nmos-registration._tcp A logical host which advertises a Registration API.
    _nmos-query._tcp A logical host which advertises a Query API.
    */
    if (q.equals(std::vector<std::string>{ "_nmos-node", "_tcp", "local" }))
    {
        LOG_INFO(get_logger(),
            "MDNS_NMOS_HTTP_Handler handling nmos node "
            "query????????????????????");
        answer.append_TXT(create_list("api_proto"), "http");
        answer.append_TXT(create_list("api_var"), "v1.3");
        answer.append_TXT(create_list("api_auth"), "false");

        answer.append_TXT(
            create_list("ver_slf"), toString_8bit(m_nmos_service.num_self()));
        answer.append_TXT(
            create_list("ver_src"), toString_8bit(m_nmos_service.num_source()));
        answer.append_TXT(
            create_list("ver_flw"), toString_8bit(m_nmos_service.num_flows()));
        answer.append_TXT(create_list("ver_dvc"),
            toString_8bit(m_nmos_service.num_devices()));
        answer.append_TXT(create_list("ver_snd"),
            toString_8bit(m_nmos_service.num_senders()));
        answer.append_TXT(create_list("ver_rcv"),
            toString_8bit(m_nmos_service.num_receivers()));
        return MDNS_IsHandled::IS_HANDLED;
    }

    if (q.equals(std::vector<std::string>{ "_nmos-register", "_tcp", "local" }))
    {
        LOG_INFO(get_logger(),
            "MDNS_NMOS_HTTP_Handler handling nmos registration query");
        return MDNS_IsHandled::IS_HANDLED;
    }
    if (q.equals(std::vector<std::string>{ "_nmos-query", "_tcp", "local" }))
    {
        LOG_INFO(
            get_logger(), "MDNS_NMOS_HTTP_Handler handling nmos query query");
        return MDNS_IsHandled::IS_HANDLED;
    }
    return MDNS_IsHandled::NOT_HANDLED_YET;
}


std::optional<iuring::IPAddress> MDNS_NMOS_HTTP_Handler::resolve_dns_request(
    const name_list_t& name_list)
{
    if (name_list.empty())
    {
        LOG_INFO(get_logger(), "empty name list in resolve_dns_request");
        return std::nullopt;
    }
    std::string hostname;
    if (StringUtils::last_item_equals(name_list, "local"))
    {
        hostname =
            StringUtils::to_string(name_list.begin(), name_list.end() - 1, ".");
    }
    else
    {
        hostname = StringUtils::to_string(name_list, ".");
    }

    LOG_INFO(get_logger(), "resolving hostname {} from name list: {}", hostname,
        StringUtils::to_string(name_list));

    get_io()->resolve_hostname(hostname,
        [this, hostname](std::expected<std::vector<iuring::IPAddress>, error::Error>
                result) {
            if (result)
            {
                for (const auto& ip : result.value())
                {
                    LOG_INFO(get_logger(), "resolved hostname '{}' to ip: {}",
                        hostname,
                        ip.to_human_readable_ip_string());
                }
            }
            else
            {
                LOG_ERROR(get_logger(), "failed to resolve hostname: {}, error: {}",
                    hostname,
                    static_cast<int>(result.error()));
            }
        });

    return std::nullopt;
}


MDNS_IsHandled MDNS_NMOS_HTTP_Handler::handle_reply(
    const std::vector<ReplyData>& replies)
{
    std::optional<iuring::IPAddress> ip_address_of_nmos_registration_server;
    std::optional<uint16_t> port_of_registration_server;
    std::optional<name_list_t> registration_srv_name;

    std::optional<std::string> api_proto_opt;
    std::optional<std::string> api_ver_opt;

    bool found = false;
    for (auto reply : replies)
    {
        if (reply.equals(std::vector<std::string>{
                "*", "_nmos-registration", "_tcp", "local" }))
        {
            LOG_INFO(get_logger(),
                "RECOGNIZED - going to contact server for registration!");
            found = true;
        }

        if (reply.equals(std::vector<std::string>{
                "*", "_nmos-register", "_tcp", "local" }))
        {
            LOG_INFO(get_logger(),
                "RECOGNIZED - going to contact server for registration!");
            found = true;
        }

        switch (reply.get_type())
        {
        default:
            LOG_INFO(get_logger(), "unhandled reply type: {} / {}",
                reply.get_type(), static_cast<int>(reply.get_type()));
            break;

        case RRType::TXT: {
            LOG_INFO(get_logger(), "TXT map is {}",
                StringUtils::to_string(reply.TXT));
            if (!reply.TXT.has_value())
            {
                LOG_ERROR(
                    get_logger(), "missing TXT record data - internal error?");
                break;
            }
            if (!reply.TXT->contains("api_ver"))
            {
                LOG_ERROR(get_logger(), "registration request has no api_ver");
                break;
            }
            if (!reply.TXT->contains("api_proto"))
            {
                LOG_ERROR(get_logger(), "registration request has no api_ver");
                break;
            }
            api_proto_opt = reply.TXT->at("api_proto");
            api_ver_opt = reply.TXT->at("api_ver");
            break;
        }

        case RRType::PTR: {
            // contains the service name:
            if (reply.PTR.has_value())
            {
                LOG_INFO(get_logger(), "service in PTR: {}",
                    StringUtils::to_string(reply.PTR.value()));
            }
            else
            {
                LOG_ERROR(get_logger(), "no reply PTR found?!?");
            }
            break;
        }

        case RRType::SRV: {
            assert(reply.SRV.has_value());
            port_of_registration_server = reply.SRV->port;
            LOG_INFO(get_logger(), "PORT OF SERVER AT {}, namelist: {}",
                port_of_registration_server.value(),
                StringUtils::to_string(reply.SRV->name_list));

            if (!ip_address_of_nmos_registration_server)
            {
                registration_srv_name = reply.SRV->name_list;
            }
            break;
        }

        case RRType::A: {
            assert(reply.A.has_value());
            ip_address_of_nmos_registration_server = reply.A.value();

            LOG_INFO(get_logger(), "NMOS - IP ADDRESS AT {}",
                ip_address_of_nmos_registration_server.value()
                    .to_human_readable_ip_string());
            break;
        }

        case RRType::AAAA: {
            // IPv6 address - log and skip for now if we don't support IPv6
            LOG_INFO(get_logger(), "AAAA (IPv6) record received - skipping");
            break;
        }
        }
    }

    if (!found)
    {
        LOG_INFO(get_logger(),
            "did not find the registration server in the MDNS reply");
        return MDNS_IsHandled::NOT_HANDLED_YET;
    }

    if (!ip_address_of_nmos_registration_server.has_value())
    {
        if (registration_srv_name.has_value())
        {
            LOG_INFO(get_logger(),
                "need to resolve registration server name: {}",
                StringUtils::to_string(registration_srv_name.value()));
            ip_address_of_nmos_registration_server =
                resolve_dns_request(registration_srv_name.value());
        }
    }

    if (!ip_address_of_nmos_registration_server.has_value())
    {
        LOG_INFO(get_logger(), "no ip address found for registration service");
        return MDNS_IsHandled::IS_HANDLED;
    }

    if (!api_proto_opt.has_value())
    {
        LOG_ERROR(get_logger(), "not registering - no api_proto provided");
        return MDNS_IsHandled::IS_HANDLED;
    }
    if (!api_ver_opt.has_value())
    {
        LOG_ERROR(get_logger(), "not registering - no api_proto provided");
        return MDNS_IsHandled::IS_HANDLED;
    }

    const auto api_proto = api_proto_opt.value();
    const auto api_ver = api_ver_opt.value();

    if (api_proto != "http" and api_proto != "https")
    {
        LOG_ERROR(get_logger(),
            "unhandled api proto, ignoring registration request: {}",
            api_proto);
        return MDNS_IsHandled::IS_HANDLED;
    }

    if (api_ver != "v1.3")
    {
        LOG_ERROR(get_logger(),
            "unhandled api version, ignoring registration request: {}",
            api_ver);
        return MDNS_IsHandled::IS_HANDLED;
    }

    m_nmos_service.start_registration(
        ip_address_of_nmos_registration_server.value(),
        port_of_registration_server);

    return MDNS_IsHandled::IS_HANDLED;
}
} // namespace mdns
