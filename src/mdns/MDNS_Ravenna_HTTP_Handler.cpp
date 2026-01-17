#include "mdns/MDNS_Service.hpp"
#include "mdns/MDNS_Ravenna_HTTP_Handler.hpp"

namespace mdns
{
    MDNS_IsHandled MDNS_Ravenna_HTTP_Handler::handle_question(const QuestionData& q, IAnswerList& answer)
    {
        if (!q.equals(std::vector<std::string>{
                "_ravenna", "_sub", "_http", "_tcp", "local" }))
        {
            return MDNS_IsHandled::NOT_HANDLED_YET;
        }

        // <vendor node id>._http._tcp
        // <user defined node name>._http._tcp
        // <vendor node id>._ravenna._sub._http._tcp
        //

        const auto hostname = create_list(get_vendor_node_name(), "local");

        const auto ipv4_string_opt = get_adapter().get_interface_ip4();
        assert(ipv4_string_opt.has_value());
        auto& ipv4_string = ipv4_string_opt.value();

        // // <vendor node id>._ravenna._sub._http._tcp.

        const auto normal_name_http =
            create_list(get_vendor_node_id(), "_http", "_tcp");
        const auto ravenna_name_http = create_list(
            get_vendor_node_id(), "_ravenna", "_sub", "_http", "_tcp");

        const auto normal_name_rtsp =
            create_list(get_vendor_node_id(), "_rtsp", "_tcp");
        const auto ravenna_name_rtsp = create_list(
            get_vendor_node_id(), "_ravenna", "_sub", "_rtsp", "_tcp");

        const auto vec = std::vector<name_list_t>{
            normal_name_http,
            ravenna_name_http,
            normal_name_rtsp,
            ravenna_name_rtsp,
        };

        for (auto it : vec)
        {
            answer.append_PTR(q.name_list, it);
            answer.append_TXT(it, "");
            answer.append_SRV(it, hostname);

            const auto addr_general =
                iuring::IPAddress::string_to_ipv4_address(
                    ipv4_string.to_human_readable_ip_string(), get_logger());
            answer.append_A(it, addr_general);
        }

        return MDNS_IsHandled::IS_HANDLED;
    }

    MDNS_IsHandled MDNS_Ravenna_HTTP_Handler::handle_reply(const std::vector<ReplyData>& )
    {
        return MDNS_IsHandled::NOT_HANDLED_YET;
    }

}