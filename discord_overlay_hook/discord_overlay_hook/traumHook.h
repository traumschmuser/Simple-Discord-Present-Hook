#pragma once
#include "tool.h"
namespace traumHook 
{
	//offsets
	uintptr_t discordHook64;
	uintptr_t discordCreateHook_offset;
	uintptr_t discordQueueEnableHook_offset;
	uintptr_t discordApplyQueued_offset;
	uintptr_t discordPresentHook_offset;

	//MH_CreateHook()
	__int64 CreateHook(__int64 pTarget, __int64 pDetour, __int64* ppOriginal) {
		return ((__int64 (*)(__int64, __int64, __int64*))(discordHook64 + discordCreateHook_offset))(pTarget, pDetour, ppOriginal);
	}
	//MH_QueueEnableHook()
	__int64 QueueEnableHook(__int64 pTarget) {
		return ((__int64 (*)(__int64))(discordHook64 + discordQueueEnableHook_offset))(pTarget);
	}
	//MH_ApplyQueued()
	__int64 ApplyQueued() {
		return ((__int64 (*)())(discordHook64 + discordApplyQueued_offset))();
	}

	//Present Hook
	__int64(*Present)(void*, __int64, __int64);
	__int64 main_hook(void* swapchain, __int64 interval, __int64 flags)
	{
		//calls your "main" function
		tool::main();
		
		//returns original Present
		return Present(swapchain, interval, flags);
	}

	bool InitializeDiscordHook()
	{
		//get module base address
		discordHook64 = (uintptr_t)GetModuleHandle(L"DiscordHook64.dll");
		if (discordHook64) {
			
			//pattern scans
			discordCreateHook_offset = memory::PatternScan("\x41\x57\x41\x56\x56\x57\x55\x53\x48\x83\xEC\x68\x4D\x89\xC6\x49\x89\xD7", "xxxxxxxxxxxxxxxxxx", discordHook64, 0xFFFFF);
			if (discordCreateHook_offset) discordCreateHook_offset -= discordHook64;
			else return false;

			discordQueueEnableHook_offset = memory::PatternScan("\x41\x56\x56\x57\x53\x48\x83\xEC\x28\x49\x89\xCE\xBF\x01\x00\x00\x00\x31\xC0\xF0\x0F\xB1\x3D", "xxxxxxxxxxxxxxxxxxxxxxx", discordHook64, 0xFFFFF);
			if (discordQueueEnableHook_offset) discordQueueEnableHook_offset -= discordHook64;
			else return false;

			discordPresentHook_offset = memory::PatternScan("\x56\x57\x53\x48\x83\xEC\x30\x44\x89\xC6", "xxxxxxxxxx", discordHook64, 0xFFFFF);
			if (discordPresentHook_offset) discordPresentHook_offset -= discordHook64;
			else return false;

			discordApplyQueued_offset = memory::PatternScan("\xE8\x00\x00\x00\x00\x85\xC0\x74\x15\x48\x8D\x0D", "x????xxxxxxx", discordHook64, 0xFFFF);
			if (discordApplyQueued_offset) discordApplyQueued_offset -= discordHook64;
			else return false;

			//resolve "ApplyQueued" offset
			discordApplyQueued_offset = *(unsigned int*)(discordHook64 + discordApplyQueued_offset + 0x1) + discordApplyQueued_offset + 0x5;
			
			//create hook
			if (CreateHook(discordHook64 + discordPresentHook_offset, (__int64)main_hook, (__int64*)&Present) != 0) return false;

			//queue hook
			if (QueueEnableHook(discordHook64 + discordPresentHook_offset) != 0) return false;

			//enable queued hooks
			if (ApplyQueued() != 0) return false;
			
			//return true if everything worked
			return true;
		}
		//return false if DiscordHook64.dll is not loaded
		return false;
	}
}