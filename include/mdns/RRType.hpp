#pragma once

namespace mdns
{
enum class RRType : uint8_t
{
    A = 1, // IP address
    NS = 2,
    MD = 3,
    CNAME = 5,
    WKKS = 11,
    PTR = 12,
    TXT = 16,
    AAAA = 28, // IPv6 address
    SRV = 33
};

}