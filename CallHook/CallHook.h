#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <atomic>
#include <cstring>
#include <intrin.h>
#include <limits>
#include <cstddef>
#include <cstdint>
#include <windows.h>

#define CALLHOOK_MAX_HOOKS 256

#pragma intrinsic(_InterlockedCompareExchange)

namespace CallHook
{
	static constexpr size_t kCallRel32Size = 5;
	static constexpr size_t kRelayCodeSize = 6;
	static constexpr size_t kRelaySize = kRelayCodeSize + sizeof(uint64_t);
	static constexpr uint32_t kPageExecuteReadWrite = 0x40;
	static constexpr uint32_t kPageExecuteRead = 0x20;
	inline LPVOID const kAllHooksMagic = reinterpret_cast<LPVOID>(static_cast<uintptr_t>(-1));

	struct HookRecord
	{
		LPVOID targetAddress;
		LPVOID relayAddress;
		int32_t originalDisplacement;
		int32_t relayDisplacement;
		bool enabled;
	};

	inline std::atomic_flag g_Lock = ATOMIC_FLAG_INIT;
	inline size_t g_HookCount = 0;
	inline HookRecord g_Hooks[CALLHOOK_MAX_HOOKS] = {};

	static inline void Lock()
	{
		while (g_Lock.test_and_set(std::memory_order_acquire))
		{
		}
	}

	static inline void Unlock()
	{
		g_Lock.clear(std::memory_order_release);
	}

	static inline HookRecord *FindHookUnlocked(LPVOID targetAddress)
	{
		for (size_t index = 0; index < g_HookCount; ++index)
		{
			if (g_Hooks[index].targetAddress == targetAddress)
			{
				return &g_Hooks[index];
			}
		}

		return nullptr;
	}

	static inline bool MakeDisplacement(uint8_t *callAddress, LPVOID targetAddress, int32_t *displacement)
	{
		const auto nextInstruction = reinterpret_cast<intptr_t>(callAddress + kCallRel32Size);
		const auto target = reinterpret_cast<intptr_t>(targetAddress);
		const auto distance = target - nextInstruction;

		if (distance < static_cast<intptr_t>((std::numeric_limits<int32_t>::min)()) ||
			distance > static_cast<intptr_t>((std::numeric_limits<int32_t>::max)()))
		{
			return false;
		}

		*displacement = static_cast<int32_t>(distance);
		return true;
	}

	static inline uintptr_t AlignUp(uintptr_t value, uintptr_t alignment)
	{
		return (value + alignment - 1) & ~(alignment - 1);
	}

	static inline bool AddOverflow(uintptr_t value, uintptr_t addend, uintptr_t *result)
	{
		*result = value + addend;
		return *result < value;
	}

	static inline LPVOID AllocateRelayNear(uint8_t *callAddress)
	{
		SYSTEM_INFO systemInfo = {};
		GetSystemInfo(&systemInfo);

		const uintptr_t allocationGranularity = systemInfo.dwAllocationGranularity;
		const uintptr_t minimumApplicationAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
		const uintptr_t maximumApplicationAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);
		const uintptr_t nextInstruction = reinterpret_cast<uintptr_t>(callAddress + kCallRel32Size);
		const uintptr_t rangeBack = static_cast<uintptr_t>((std::numeric_limits<int32_t>::max)()) + 1;
		const uintptr_t rangeForward = static_cast<uintptr_t>((std::numeric_limits<int32_t>::max)());

		uintptr_t minimumAddress = minimumApplicationAddress;
		if (nextInstruction > rangeBack)
		{
			minimumAddress = nextInstruction - rangeBack;
			if (minimumAddress < minimumApplicationAddress)
			{
				minimumAddress = minimumApplicationAddress;
			}
		}

		uintptr_t maximumAddress = maximumApplicationAddress;
		uintptr_t forwardLimit = 0;
		if (!AddOverflow(nextInstruction, rangeForward, &forwardLimit) && forwardLimit < maximumAddress)
		{
			maximumAddress = forwardLimit;
		}

		uintptr_t queryAddress = minimumAddress;
		while (queryAddress <= maximumAddress)
		{
			MEMORY_BASIC_INFORMATION memoryInfo = {};
			if (VirtualQuery(reinterpret_cast<LPCVOID>(queryAddress), &memoryInfo, sizeof(memoryInfo)) == 0)
			{
				break;
			}

			const uintptr_t regionBase = reinterpret_cast<uintptr_t>(memoryInfo.BaseAddress);
			uintptr_t regionEnd = 0;
			if (AddOverflow(regionBase, memoryInfo.RegionSize, &regionEnd))
			{
				break;
			}

			if (memoryInfo.State == MEM_FREE)
			{
				uintptr_t candidate = regionBase > minimumAddress ? regionBase : minimumAddress;
				candidate = AlignUp(candidate, allocationGranularity);

				uintptr_t candidateEnd = 0;
				if (!AddOverflow(candidate, kRelaySize, &candidateEnd) &&
					candidate <= maximumAddress &&
					candidateEnd <= regionEnd)
				{
					LPVOID relayAddress = VirtualAlloc(
						reinterpret_cast<LPVOID>(candidate),
						kRelaySize,
						MEM_RESERVE | MEM_COMMIT,
						kPageExecuteReadWrite);

					if (relayAddress != nullptr)
					{
						return relayAddress;
					}
				}
			}

			if (regionEnd <= queryAddress)
			{
				break;
			}

			queryAddress = regionEnd;
		}

		return nullptr;
	}

	static inline bool WriteRelay(LPVOID relayAddress, LPVOID targetCallBack)
	{
		static constexpr uint8_t kRelayCode[kRelayCodeSize] =
			{
				0xFF,
				0x25,
				0x00,
				0x00,
				0x00,
				0x00,
			};

		auto *relayBytes = reinterpret_cast<uint8_t *>(relayAddress);
		const uint64_t target = reinterpret_cast<uint64_t>(targetCallBack);

		std::memcpy(relayBytes, kRelayCode, sizeof(kRelayCode));
		std::memcpy(relayBytes + kRelayCodeSize, &target, sizeof(target));

		unsigned long ignored = 0;
		if (VirtualProtect(relayAddress, kRelaySize, kPageExecuteRead, &ignored) == 0)
		{
			return false;
		}

		return FlushInstructionCache(GetCurrentProcess(), relayAddress, kRelaySize) != 0;
	}

	static inline void FreeRelay(LPVOID relayAddress)
	{
		if (relayAddress != nullptr)
		{
			VirtualFree(relayAddress, 0, MEM_RELEASE);
		}
	}

	static inline bool ReadCallDisplacement(uint8_t *callAddress, int32_t *displacement)
	{
		std::memcpy(displacement, callAddress + 1, sizeof(*displacement));
		return true;
	}

	static inline bool PatchCallDisplacement(uint8_t *callAddress, int32_t expectedDisplacement, int32_t desiredDisplacement)
	{
		unsigned long oldProtect = 0;
		if (VirtualProtect(callAddress, kCallRel32Size, kPageExecuteReadWrite, &oldProtect) == 0)
		{
			return false;
		}

		const long previous = _InterlockedCompareExchange(
			reinterpret_cast<volatile long *>(callAddress + 1),
			static_cast<long>(desiredDisplacement),
			static_cast<long>(expectedDisplacement));

		unsigned long ignored = 0;
		VirtualProtect(callAddress, kCallRel32Size, oldProtect, &ignored);
		FlushInstructionCache(GetCurrentProcess(), callAddress, kCallRel32Size);
		return previous == static_cast<long>(expectedDisplacement);
	}

	static inline bool SetHookStateUnlocked(bool enableHook, HookRecord *hook)
	{
		if (hook->enabled == enableHook)
		{
			return true;
		}

		auto *callAddress = reinterpret_cast<uint8_t *>(hook->targetAddress);
		const int32_t expectedDisplacement = enableHook ? hook->originalDisplacement : hook->relayDisplacement;
		const int32_t desiredDisplacement = enableHook ? hook->relayDisplacement : hook->originalDisplacement;

		if (!PatchCallDisplacement(callAddress, expectedDisplacement, desiredDisplacement))
		{
			return false;
		}

		hook->enabled = enableHook;
		return true;
	}

	template <bool enableHook>
	static inline bool CreateHook(LPVOID targetAddress, LPVOID targetCallBack)
	{
		bool success = false;
		LPVOID relayAddress = nullptr;
		Lock();

		do
		{
			if (targetAddress == nullptr || targetCallBack == nullptr)
			{
				break;
			}

			if (g_HookCount >= CALLHOOK_MAX_HOOKS || FindHookUnlocked(targetAddress) != nullptr)
			{
				break;
			}

			auto *callAddress = reinterpret_cast<uint8_t *>(targetAddress);
			int32_t originalDisplacement = 0;
			int32_t relayDisplacement = 0;

			relayAddress = AllocateRelayNear(callAddress);
			if (relayAddress == nullptr ||
				!WriteRelay(relayAddress, targetCallBack) ||
				!ReadCallDisplacement(callAddress, &originalDisplacement) ||
				!MakeDisplacement(callAddress, relayAddress, &relayDisplacement))
			{
				break;
			}

			HookRecord record = {};
			record.targetAddress = targetAddress;
			record.relayAddress = relayAddress;
			record.originalDisplacement = originalDisplacement;
			record.relayDisplacement = relayDisplacement;
			record.enabled = false;

			if (enableHook)
			{
				if (!PatchCallDisplacement(callAddress, originalDisplacement, relayDisplacement))
				{
					break;
				}

				record.enabled = true;
			}

			g_Hooks[g_HookCount] = record;
			++g_HookCount;
			relayAddress = nullptr;
			success = true;
		} while (false);

		if (!success)
		{
			FreeRelay(relayAddress);
		}

		Unlock();
		return success;
	}

	static inline bool SetHookState(LPVOID targetAddress, bool enableHook)
	{
		bool success = false;
		Lock();

		do
		{
			if (targetAddress == kAllHooksMagic)
			{
				success = true;
				for (size_t index = 0; index < g_HookCount; ++index)
				{
					if (!SetHookStateUnlocked(enableHook, &g_Hooks[index]))
					{
						success = false;
					}
				}

				break;
			}

			if (targetAddress == nullptr)
			{
				break;
			}

			HookRecord *hook = FindHookUnlocked(targetAddress);
			if (hook == nullptr)
			{
				break;
			}

			success = SetHookStateUnlocked(enableHook, hook);
		} while (false);

		Unlock();
		return success;
	}

	inline bool Uninitialize()
	{
		bool success = true;
		Lock();

		for (size_t index = g_HookCount; index > 0; --index)
		{
			HookRecord *hook = &g_Hooks[index - 1];
			if (!hook->enabled)
			{
				continue;
			}

			auto *callAddress = reinterpret_cast<uint8_t *>(hook->targetAddress);
			if (PatchCallDisplacement(callAddress, hook->relayDisplacement, hook->originalDisplacement))
			{
				hook->enabled = false;
				continue;
			}

			success = false;
		}

		if (success)
		{
			for (size_t index = 0; index < g_HookCount; ++index)
			{
				FreeRelay(g_Hooks[index].relayAddress);
				g_Hooks[index] = {};
			}

			g_HookCount = 0;
		}

		Unlock();
		return success;
	}
}
