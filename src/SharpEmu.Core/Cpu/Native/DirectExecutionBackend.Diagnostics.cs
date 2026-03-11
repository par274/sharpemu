// Copyright (C) 2026 SharpEmu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using SharpEmu.HLE;

namespace SharpEmu.Core.Cpu.Native;

public sealed partial class DirectExecutionBackend
{

	private void RecordRecentImportTrace(string traceLine)
	{
		_recentImportTrace[_recentImportTraceWriteIndex] = traceLine;
		_recentImportTraceWriteIndex = (_recentImportTraceWriteIndex + 1) % _recentImportTrace.Length;
		if (_recentImportTraceCount < _recentImportTrace.Length)
		{
			_recentImportTraceCount++;
		}
	}

	private void DumpRecentImportTrace()
	{
		if (_recentImportTraceCount == 0)
		{
			return;
		}
		Console.Error.WriteLine($"[LOADER][INFO]   Recent import calls ({_recentImportTraceCount}):");
		int num = (_recentImportTraceWriteIndex - _recentImportTraceCount + _recentImportTrace.Length) % _recentImportTrace.Length;
		for (int i = 0; i < _recentImportTraceCount; i++)
		{
			int num2 = (num + i) % _recentImportTrace.Length;
			string text = _recentImportTrace[num2];
			if (!string.IsNullOrEmpty(text))
			{
				Console.Error.WriteLine("[LOADER][INFO]     " + text);
			}
		}
	}

	private unsafe static List<ulong> ScanSuspiciousResolverPointers(ulong scanStart, ulong scanEnd)
	{
		if (scanEnd <= scanStart)
		{
			return new List<ulong>(0);
		}
		int num = 0;
		int num2 = 0;
		List<ulong> list = new List<ulong>(16);
		ulong num3 = scanStart;
		MEMORY_BASIC_INFORMATION64 lpBuffer;
		while (num3 < scanEnd && VirtualQuery((void*)num3, out lpBuffer, (nuint)sizeof(MEMORY_BASIC_INFORMATION64)) != 0)
		{
			ulong baseAddress = lpBuffer.BaseAddress;
			ulong num4 = baseAddress + lpBuffer.RegionSize;
			if (num4 <= num3)
			{
				break;
			}
			ulong value = Math.Max(num3, baseAddress);
			ulong num5 = Math.Min(num4, scanEnd);
			if (lpBuffer.State == 4096 && IsReadableProtection(lpBuffer.Protect) && !IsExecutableProtection(lpBuffer.Protect))
			{
				ulong num6 = AlignUp(value, 8uL);
				for (ulong num7 = num6; num7 + 8 <= num5; num7 += 8)
				{
					ulong value2 = *(ulong*)num7;
					if (IsUnresolvedSentinel(value2))
					{
						num++;
						list.Add(num7);
						if (num2 < 32)
						{
							Console.Error.WriteLine($"[LOADER][INFO] Suspicious unresolved pointer: slot=0x{num7:X16} value=0x{value2:X16}");
							num2++;
						}
						if (num >= 16384)
						{
							Console.Error.WriteLine($"[LOADER][WARNING] Suspicious unresolved pointer scan reached cap ({16384}); truncating.");
							return list;
						}
					}
				}
			}
			num3 = num5;
		}
		if (num != 0)
		{
			Console.Error.WriteLine($"[LOADER][WARNING] Suspicious unresolved pointer hits: {num}");
		}
		return list;
	}

	private void ProbeReturnRip(ulong returnRip, long dispatchIndex)
	{
		if (_cpuContext == null || returnRip == 0)
		{
			return;
		}
		Span<byte> destination = stackalloc byte[128];
		if (!_cpuContext.Memory.TryRead(returnRip, destination))
		{
			Console.Error.WriteLine($"[LOADER][TRACE] Import#{dispatchIndex} return-rip probe: unreadable @0x{returnRip:X16}");
			return;
		}
		string value = BitConverter.ToString(destination.ToArray()).Replace("-", " ");
		Console.Error.WriteLine($"[LOADER][TRACE] Import#{dispatchIndex} return-rip bytes @0x{returnRip:X16}: {value}");
		if (destination[0] == byte.MaxValue && (destination[1] == 21 || destination[1] == 37))
		{
			int num = BitConverter.ToInt32(destination.Slice(2, 4));
			ulong num2 = returnRip + 6 + (ulong)num;
			if (_cpuContext.TryReadUInt64(num2, out var value2))
			{
				Console.Error.WriteLine($"[LOADER][TRACE] Import#{dispatchIndex} return-rip slot: [0x{num2:X16}] = 0x{value2:X16}");
			}
		}
		if (destination[0] == 72 && destination[1] == 139 && destination[2] == 5)
		{
			int num3 = BitConverter.ToInt32(destination.Slice(3, 4));
			ulong num4 = returnRip + 7 + (ulong)num3;
			if (_cpuContext.TryReadUInt64(num4, out var value3))
			{
				Console.Error.WriteLine($"[LOADER][TRACE] Import#{dispatchIndex} return-rip mov-slot: [0x{num4:X16}] = 0x{value3:X16}");
			}
		}
		for (int i = 0; i + 6 <= destination.Length; i++)
		{
			if (destination[i] == byte.MaxValue && (destination[i + 1] == 21 || destination[i + 1] == 37))
			{
				int num5 = BitConverter.ToInt32(destination.Slice(i + 2, 4));
				ulong num6 = returnRip + (ulong)i;
				ulong num7 = num6 + 6 + (ulong)num5;
				if (_cpuContext.TryReadUInt64(num7, out var value4))
				{
					Console.Error.WriteLine($"[LOADER][TRACE] Import#{dispatchIndex} near-indirect @{num6:X16}: slot=0x{num7:X16} val=0x{value4:X16}");
				}
			}
		}
	}

	private static bool IsUnresolvedSentinel(ulong value)
	{
		return value == 65534 || value == 4294967294u || value == 18446744073709551614uL;
	}

	private static bool IsPlausibleReturnAddress(ulong address)
	{
		return address >= 12884901888L && address < 17592186044416L && !IsUnresolvedSentinel(address);
	}

	private static bool TryGetPlausibleReturnFromStack(ulong rsp, out ulong returnRip, out ulong nextRsp)
	{
		returnRip = 0uL;
		nextRsp = rsp;
		if (rsp <= 65536 || rsp >= 140737488355328L)
		{
			return false;
		}
		ulong num = rsp & 0xFFFFFFFFFFFFFFF8uL;
		ulong num2 = ((num >= 8) ? (num - 8) : num);
		for (int i = 0; i < 24; i++)
		{
			ulong num3 = num2 + (ulong)((long)i * 8L);
			if (TryReadStackU64(num3, out var value) && IsLikelyReturnAddress(value))
			{
				returnRip = value;
				nextRsp = num3 + 8;
				return true;
			}
		}
		for (ulong num4 = 1uL; num4 < 8; num4++)
		{
			for (int j = 0; j < 24; j++)
			{
				ulong num5 = rsp + num4 + (ulong)((long)j * 8L);
				if (TryReadStackU64(num5, out var value2) && IsLikelyReturnAddress(value2))
				{
					returnRip = value2;
					ulong num6 = num5 + 8;
					nextRsp = (num6 + 7) & 0xFFFFFFFFFFFFFFF8uL;
					return true;
				}
			}
		}
		return false;
	}

	private unsafe static bool TryReadStackU64(ulong address, out ulong value)
	{
		value = 0uL;
		if (address <= 65536 || address >= 140737488355328L)
		{
			return false;
		}
		if (VirtualQuery((void*)address, out var lpBuffer, (nuint)sizeof(MEMORY_BASIC_INFORMATION64)) == 0)
		{
			return false;
		}
		ulong num = lpBuffer.BaseAddress + lpBuffer.RegionSize;
		if (num < lpBuffer.BaseAddress || address > num - 8)
		{
			return false;
		}
		if (lpBuffer.State != 4096 || !IsReadableProtection(lpBuffer.Protect))
		{
			return false;
		}
		try
		{
			value = *(ulong*)address;
			return true;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsLikelyReturnAddress(ulong address)
	{
		if (!IsPlausibleReturnAddress(address))
		{
			return false;
		}
		return IsExecutableAddress(address);
	}

	private unsafe static bool IsExecutableAddress(ulong address)
	{
		if (VirtualQuery((void*)address, out var lpBuffer, (nuint)sizeof(MEMORY_BASIC_INFORMATION64)) == 0)
		{
			return false;
		}
		return lpBuffer.State == 4096 && IsExecutableProtection(lpBuffer.Protect);
	}

	private static ulong AlignUp(ulong value, ulong alignment)
	{
		if (alignment == 0)
		{
			return value;
		}
		ulong num = alignment - 1;
		return (value + num) & ~num;
	}

	private static bool IsReadableProtection(uint protect)
	{
		if ((protect & 0x100) != 0 || (protect & 1) != 0)
		{
			return false;
		}
		return (protect & 0xEE) != 0;
	}

	private static bool IsExecutableProtection(uint protect)
	{
		return (protect & 0xF0) != 0;
	}
}
