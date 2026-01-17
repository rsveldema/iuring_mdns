#pragma once

#include <string>
#include <queue>

#include <slogger/ILogger.hpp>

#include <iuring/IOUringInterface.hpp>

#include <urtsched/RealtimeKernel.hpp>
#include <urtsched/Service.hpp>

namespace mdns
{
using transaction_id_t = uint16_t;

enum class MDNS_class : uint16_t
{
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4
};


enum class DNS_RecordType
{
    A = 1,     // ipv4 address
    PTR = 12,  // domain name pointer
    TXT = 16,  // text string
    SRV = 33,  // server selection
    AAAA = 28, // ipv6 address
};


struct __attribute__((packed)) MDNS_Header
{
private:
    transaction_id_t m_transaction_id;
    uint8_t m_flags0;
    uint8_t m_flags1;
    uint16_t m_num_questions;
    uint16_t m_num_answers;
    uint16_t m_num_auth_resource_records; // rr
    uint16_t m_num_additional_resource_reconrds;

public:
    enum class MessageType
    {
        QUERY,
        REPLY
    };

    enum class Opcode
    {
        // The type can be QUERY (standard query, 0),
        // IQUERY (inverse query, 1),
        // or STATUS (server status request, 2)
        QUERY,
        IQUERY,
        STATUS
    };

    static constexpr uint8_t BIT_SHIFT_QR =
        7; // Indicates if the message is a query (0) or a reply (1)	1
    static constexpr uint8_t BIT_SHIFT_OPCODE =
        3; // The type can be QUERY (standard query, 0), IQUERY (inverse query,
           // 1), or STATUS (server status request, 2)	4
    static constexpr uint8_t BIT_SHIFT_AA =
        2; // Authoritative Answer, in a response, indicates if the DNS server
           // is authoritative for the queried hostname	1
    static constexpr uint8_t BIT_SHIFT_TC =
        1; // TrunCation, indicates that this message was truncated due to
           // excessive length	1
    static constexpr uint8_t BIT_SHIFT_RD =
        0; // Recursion Desired, indicates if the client means a recursive query
           // 1
    static constexpr uint8_t BIT_SHIFT_RA =
        5; // Recursion Available, in a response, indicates if the replying DNS
           // server supports recursion	1
    static constexpr uint8_t BIT_SHIFT_Z =
        4; // Zero, reserved for future use	3
    static constexpr uint8_t BIT_SHIFT_RCODE =
        0; // Response code, can be NOERROR (0), FORMERR (1, Format error),
           // SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.

    MDNS_Header(MessageType type, transaction_id_t id, uint16_t num_answers,
        uint16_t num_questions)
    {
        m_transaction_id = ntohs(id);
        switch (type)
        {
        case MessageType::QUERY:
            m_flags0 = (0 << BIT_SHIFT_QR) | (0 << BIT_SHIFT_AA);
            break;
        case MessageType::REPLY:
            m_flags0 = (1 << BIT_SHIFT_QR) | (1 << BIT_SHIFT_AA);
            break;
        }
        m_flags1 = 0;
        m_num_questions = ntohs(num_questions);
        m_num_answers = ntohs(num_answers);
        m_num_auth_resource_records = 0;
        m_num_additional_resource_reconrds = 0;
    }

    transaction_id_t get_transaction_id() const
    {
        return ntohs(m_transaction_id);
    }


    uint16_t get_num_questions() const
    {
        return htons(m_num_questions);
    }

    uint16_t get_num_answers() const
    {
        return htons(m_num_answers);
    }

    MessageType get_message_type() const
    {
        return (m_flags0 & (1 << BIT_SHIFT_QR)) ? MessageType::REPLY :
                                                  MessageType::QUERY;
    }

    Opcode get_opcode() const
    {
        int op_int = (m_flags0 >> BIT_SHIFT_OPCODE) & 0b1111;
        return static_cast<Opcode>(op_int);
    }

    bool is_authorative() const
    {
        return m_flags0 & (1 << BIT_SHIFT_AA);
    }

    bool is_truncated() const
    {
        return m_flags0 & (1 << BIT_SHIFT_TC);
    }

    bool recursion_desired() const
    {
        return m_flags0 & (1 << BIT_SHIFT_RD);
    }

    bool recursion_available() const
    {
        return m_flags1 & (1 << BIT_SHIFT_RA);
    }

    int get_response_code() const
    {
        return (m_flags1 >> BIT_SHIFT_RCODE) & 0b1111;
    }
};
}

