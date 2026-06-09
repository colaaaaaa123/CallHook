# CallHook

This fork is a Windows x64 header-only call-site hook library. It rewrites the 4-byte displacement of an existing `CALL rel32` instruction in the caller, sends that call site to a nearby relay block, and then jumps to the custom callback function.

## Requirements

- Windows x64, MSVC, and C++17 or later.
- The target address must point to the first byte of a `CALL rel32` instruction.
- The callback function must use the same calling convention, parameter list, and return value as the original `CALL` target. The original call site still pushes the return address; the relay block only transfers control to the callback function.

## Basic Usage

```cpp
#include "CallHook.h"

int Hk_Foo(int value)
{
	return value + 100;
}

bool InstallFooHook()
{
	auto *Addr_Foo = reinterpret_cast<LPVOID>(0x140114514);
	return CallHook::CreateHook<true>(Addr_Foo, reinterpret_cast<LPVOID>(&Hk_Foo));
}
```

`CreateHook<true>(...)` creates and enables a hook. `CreateHook<false>(...)` only registers the hook and creates the relay block; call `SetHookState(targetAddress, true)` later to enable it.

## Enable and Disable

```cpp
auto *Addr_Foo = reinterpret_cast<LPVOID>(0x140114514);

bool status{};

CallHook::SetHookState(Addr_Foo, false);
status = CallHook::SetHookState(Addr_Foo, true);

CallHook::SetHookState(CallHook::kAllHooksMagic, false);
status = CallHook::SetHookState(CallHook::kAllHooksMagic, true);
```

## Unload

```cpp
CallHook::Uninitialize();
```
