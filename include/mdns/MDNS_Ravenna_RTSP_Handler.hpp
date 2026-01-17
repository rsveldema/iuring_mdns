#pragma once

#include "MDNS_Service.hpp"

namespace mdns
{
// for ravenna:
class MDNS_Ravenna_RTSP_Handler : public IMDNS_Handler
{
public:
    using IMDNS_Handler::IMDNS_Handler;

    MDNS_IsHandled handle_question(const QuestionData& q, IAnswerList& answer) override;
    MDNS_IsHandled handle_reply(const std::vector<ReplyData>& reply) override;
};

} // namespace mdns