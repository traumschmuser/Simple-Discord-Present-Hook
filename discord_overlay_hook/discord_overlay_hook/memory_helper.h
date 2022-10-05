#pragma once
#include <Windows.h>

namespace memory
{
	uintptr_t PatternScan(const char* pattern, const char* mask, uintptr_t begin, unsigned int size);
}
