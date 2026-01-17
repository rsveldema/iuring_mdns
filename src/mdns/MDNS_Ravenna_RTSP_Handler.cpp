#include "mdns/MDNS_Service.hpp"
#include "mdns/MDNS_Ravenna_RTSP_Handler.hpp"

namespace mdns
{
    MDNS_IsHandled MDNS_Ravenna_RTSP_Handler::handle_question(const QuestionData& q, [[maybe_unused]] IAnswerList& answer)
    {
        if (! q.equals(std::vector<std::string>{
                "_ravenna", "_sub", "_rtsp", "_tcp", "local" }))
        {
            return MDNS_IsHandled::NOT_HANDLED_YET;
        }

        fprintf(stderr, "MDNS_RTSP_Handler handling ravenna rtsp query\n");

        return MDNS_IsHandled::IS_HANDLED;
    }


    MDNS_IsHandled MDNS_Ravenna_RTSP_Handler::handle_reply(const std::vector<ReplyData>& )
    {
        return MDNS_IsHandled::NOT_HANDLED_YET;
    }

}