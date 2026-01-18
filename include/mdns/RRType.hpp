#pragma once

namespace mdns
{
enum class RRType : uint8_t
{
    A = 1,      // IP address
    NS = 2,     // Name Server
    MD = 3,     // Mail Destination (obsolete)
    MF = 4,     // Mail Forwarder (obsolete)
    CNAME = 5,  // Canonical Name
    SOA = 6,    // Start of Authority
    MB = 7,     // Mailbox domain name
    MG = 8,     // Mail Group member
    MR = 9,     // Mail Rename domain name
    NULL_RR = 10, // NULL RR
    WKKS = 11,  // Well Known Services
    PTR = 12,   // Domain name pointer
    TXT = 16,   // Text strings
    AAAA = 28,  // IPv6 address
    SRV = 33    // Server Selection
};

}