#pragma once
#include "pch.h"
#include <atomic>

class Sha256Helper {
private:

public:
    static std::string CalculateFileSHA256(const std::wstring& filePath);
};