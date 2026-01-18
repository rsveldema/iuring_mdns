#pragma once

#include <format>
#include <map>
#include <string>
#include <vector>

#include <iuring/IOUringInterface.hpp>

#include <slogger/ILogger.hpp>
#include <slogger/StringUtils.hpp>

#include <urtsched/RealtimeKernel.hpp>
#include <urtsched/Service.hpp>

#include "MDNS_Header.hpp"

#include "RRType.hpp"

#include "QuestionData.hpp"

namespace mdns
{
using name_list_t = std::vector<std::string>;


// if SRV then payload is pre-decoded here:
struct SRV_payload
{
    uint16_t prio;
    uint16_t weight;
    uint16_t port;
    name_list_t name_list;
};

struct ReplyData : public StringUtils::ToStringMixin
{
    std::vector<std::string> name_list;
    uint16_t type;
    MDNS_class clazz;
    std::string payload;

    std::optional<SRV_payload> SRV;
    std::optional<iuring::IPAddress> A;
    std::optional<name_list_t> PTR;
    std::optional<std::map<std::string, std::string>> TXT;

    ReplyData(const std::vector<std::string>& _name_list, const uint16_t _type,
        const MDNS_class _clazz, const std::string& _payload,
        const std::optional<SRV_payload>& _SRV,
        const std::optional<iuring::IPAddress>& _A,
        const std::optional<name_list_t>& _PTR,
        const std::optional<std::map<std::string, std::string>>& _TXT)
        : name_list(_name_list)
        , type(_type)
        , clazz(_clazz)
        , payload(_payload)
        , SRV(_SRV)
        , A(_A)
        , PTR(_PTR)
        , TXT(_TXT)
    {
    }

    RRType get_type() const
    {
        return static_cast<RRType>(type);
    }

    std::string to_string() const override
    {
        return StringUtils::to_string(name_list);
    }

    /** @brief compares with possible wildcard entries
     * 
     * @param to check against. for example: *.b.c whill match x.b.c registered service
     */
    bool equals(const std::vector<std::string>& s) const
    {
        if (name_list.size() != s.size())
        {
            return false;
        }
        for (size_t i = 0; i < name_list.size(); i++)
        {
            if (s[i] == "*")
            {
                continue;
            }
            if (name_list[i] != s[i])
            {
                return false;
            }
        }
        return true;
    }
};

class IAnswerList
{
public:
    virtual void append_PTR(
        const name_list_t& name, const name_list_t& value) = 0;
    virtual void append_TXT(
        const name_list_t& name, const std::string& txt) = 0;
    virtual void append_SRV(
        const name_list_t& name, const name_list_t& hostname_list) = 0;
    virtual void append_A(const name_list_t& name, const in_addr& addr) = 0;
};

enum class MDNS_IsHandled
{
    IS_HANDLED,
    NOT_HANDLED_YET
};

class IMDNS_Handler
{
public:
    IMDNS_Handler(const std::shared_ptr<iuring::IOUringInterface>& network,
        logging::ILogger& logger, iuring::NetworkAdapter& adapter)
        : m_io(network)
        , m_logger(logger)
        , m_adapter(adapter)
    {
    }

    iuring::NetworkAdapter& get_adapter()
    {
        return m_adapter;
    }


    virtual MDNS_IsHandled handle_question(
        const QuestionData& question, IAnswerList& answer) = 0;
    virtual MDNS_IsHandled handle_reply(
        const std::vector<ReplyData>& question) = 0;

    const std::shared_ptr<iuring::IOUringInterface> get_io()
    {
        return m_io;
    }

    logging::ILogger& get_logger()
    {
        return m_logger;
    }

private:
    const std::shared_ptr<iuring::IOUringInterface> m_io;
    logging::ILogger& m_logger;
    iuring::NetworkAdapter& m_adapter;
};

} // namespace mdns