#pragma once

#include <vector>
#include <string>
#include <cstdint>

#include "MDNS_Header.hpp"


namespace mdns
{
struct QuestionData
{
    std::vector<std::string> name_list;
    uint16_t type;
    MDNS_class clazz;
    bool question_unicast;

    bool equals(const std::vector<std::string>& s) const
    {
        return name_list == s;
    }
};

} // namespace mdns