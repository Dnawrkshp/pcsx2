/*  PCSX2 - PS2 Emulator for PCs
 *  Copyright (C) 2002-2020  PCSX2 Dev Team
 *
 *  PCSX2 is free software: you can redistribute it and/or modify it under the terms
 *  of the GNU Lesser General Public License as published by the Free Software Found-
 *  ation, either version 3 of the License, or (at your option) any later version.
 *
 *  PCSX2 is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *  PURPOSE.  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with PCSX2.
 *  If not, see <http://www.gnu.org/licenses/>.
 */

 /* A reference client implementation for interfacing with PINE is available
  * here: https://code.govanify.com/govanify/pine/ */

#pragma once

  // PINE uses a concept of "slot" to be able to communicate with multiple
  // emulators at the same time, each slot should be unique to each emulator to
  // allow PnP and configurable by the end user so that several runs don't
  // conflict with each others
#define PINE_DEFAULT_SLOT 28011
#define PINE_EMULATOR_NAME "pcsx2"

#include <thread>
#include <string>
#include <vector>
#include <atomic>
#include <span>
#ifdef _WIN32
#include <WinSock2.h>
#include <windows.h>
#endif

extern int g_pine_slot;


class PINEServer
{
	std::thread m_thread;

protected:
#ifdef _WIN32
	// windows claim to have support for AF_UNIX sockets but that is a blatant lie,
	// their SDK won't even run their own examples, so we go on TCP sockets.
	SOCKET m_sock = INVALID_SOCKET;
	// the message socket used in thread's accept().
	SOCKET m_msgsock = INVALID_SOCKET;
#else
	// absolute path of the socket. Stored in XDG_RUNTIME_DIR, if unset /tmp
	std::string m_socket_name;
	int m_sock = 0;
	// the message socket used in thread's accept().
	int m_msgsock = 0;
#endif


	/**
	 * Maximum memory used by an IPC message request.
	 * Equivalent to 50,000 Write64 requests.
	 */
#define MAX_IPC_SIZE 650000

	 /**
	  * Maximum memory used by an IPC message reply.
	  * Equivalent to 50,000 Read64 replies.
	  */
#define MAX_IPC_RETURN_SIZE 1000000

	/**
	 * IPC return buffer.
	 * A preallocated buffer used to store all IPC replies.
	 * to the size of 50.000 MsgWrite64 IPC calls.
	 */
	std::vector<u8> m_ret_buffer{};

	/**
	 * IPC messages buffer.
	 * A preallocated buffer used to store all IPC messages.
	 */
	std::vector<u8> m_ipc_buffer{};

	/**
	 * IPC Command messages opcodes.
	 * A list of possible operations possible by the IPC.
	 * Each one of them is what we call an "opcode" and is the first
	 * byte sent by the IPC to differentiate between commands.
	 */
	enum IPCCommand : unsigned char
	{
		MsgRead8 = 0, /**< Read 8 bit value to memory. */
		MsgRead16 = 1, /**< Read 16 bit value to memory. */
		MsgRead32 = 2, /**< Read 32 bit value to memory. */
		MsgRead64 = 3, /**< Read 64 bit value to memory. */
		MsgWrite8 = 4, /**< Write 8 bit value to memory. */
		MsgWrite16 = 5, /**< Write 16 bit value to memory. */
		MsgWrite32 = 6, /**< Write 32 bit value to memory. */
		MsgWrite64 = 7, /**< Write 64 bit value to memory. */
		MsgVersion = 8, /**< Returns PCSX2 version. */
		MsgSaveState = 9, /**< Saves a savestate. */
		MsgLoadState = 0xA, /**< Loads a savestate. */
		MsgTitle = 0xB, /**< Returns the game title. */
		MsgID = 0xC, /**< Returns the game ID. */
		MsgUUID = 0xD, /**< Returns the game UUID. */
		MsgGameVersion = 0xE, /**< Returns the game verion. */
		MsgStatus = 0xF, /**< Returns the emulator status. */

		MsgReadN = 0x64, /** */
		MsgWriteN = 0x65, /** */
		MsgFrameAdvance = 0x66, /** */
		MsgResume = 0x67, /** */
		MsgPause = 0x68, /** */
		MsgRestart = 0x69, /** */
		MsgStop = 0x6A, /** */
		MsgGetFrameBuffer = 0x6B, /** */
		MsgSetPad = 0x6C, /** */
		MsgGetVmPtr = 0x6D, /** */
		MsgSetDynamicSetting = 0x6E, /** */
		MsgUnimplemented = 0xFF /**< Unimplemented IPC message. */
	};

	/**
	 * IPC Command messages opcodes.
	 * A list of possible operations possible by the IPC.
	 * Each one of them is what we call an "opcode" and is the first
	 * byte sent by the IPC to differentiate between commands.
	 */
	enum DynamicSettingId : unsigned char
	{
		DynamicSettingFrameSleepWait = 0, /**< If true, FrameStep sleeps while waiting for next frame command. */
		DynamicSettingDisableRendering = 1, /**< If true, Renderer is set to NULL. */
		DynamicSettingReloadConfig = 2, /**< Reloads PCSX2 config file */
		DynamicSettingIdUnimplemented = 0xFF /**< Unimplemented DynamicSettingId. */
	};

	/**
	 * Emulator status enum.
	 * A list of possible emulator statuses.
	 */
	enum EmuStatus : uint32_t
	{
		Running = 0, /**< Game is running */
		Paused = 1, /**< Game is paused */
		Shutdown = 2 /**< Game is shutdown */
	};

	/**
	 * IPC message buffer.
	 * A list of all needed fields to store an IPC message.
	 */
	struct IPCBuffer
	{
		int size; /**< Size of the buffer. */
		std::vector<u8> buffer; /**< Buffer. */
	};

	/**
	 * IPC result codes.
	 * A list of possible result codes the IPC can send back.
	 * Each one of them is what we call an "opcode" or "tag" and is the
	 * first byte sent by the IPC to differentiate between results.
	 */
	enum IPCResult : unsigned char
	{
		IPC_OK = 0, /**< IPC command successfully completed. */
		IPC_FAIL = 0xFF /**< IPC command failed to complete. */
	};

	// Thread used to relay IPC commands.
	void MainLoop();

	/**
	 * Internal function, Parses an IPC command.
	 * buf: buffer containing the IPC command.
	 * buf_size: size of the buffer announced.
	 * ret_buffer: buffer that will be used to send the reply.
	 * return value: IPCBuffer containing a buffer with the result
	 *               of the command and its size.
	 */
	IPCBuffer ParseCommand(std::span<u8> buf, std::vector<u8>& ret_buffer, u32 buf_size);

	/**
	 * Formats an IPC buffer
	 * ret_buffer: return buffer to use.
	 * size: size of the IPC buffer.
	 * return value: buffer containing the status code allocated of size
	 */
	static inline std::vector<u8>& MakeOkIPC(std::vector<u8>& ret_buffer, uint32_t size);
	static inline std::vector<u8>& MakeFailIPC(std::vector<u8>& ret_buffer, uint32_t size);

	/**
	 * Initializes an open socket for IPC communication.
	 * return value: -1 if a fatal failure happened, 0 otherwise.
	 */
	int StartSocket();

	/**
	 * Converts a primitive value to bytes in little endian
	 * res_vector: the vector to modify
	 * res: the value to convert
	 * i: where to insert it into the vector
	 * NB: implicitely inlined
	 */
	template <typename T>
	static void ToResultVector(std::vector<u8>& res_vector, T res, int i)
	{
		memcpy(&res_vector[i], (char*)&res, sizeof(T));
	}

	/**
	 * Converts bytes in little endian to a primitive value
	 * span: the span to convert
	 * i: where to load it from the span
	 * return value: the converted value
	 * NB: implicitely inlined
	 */
	template <typename T>
	static T FromSpan(std::span<u8> span, int i)
	{
		return *(T*)(&span[i]);
	}

	/**
	 * Ensures an IPC message isn't too big.
	 * return value: false if checks failed, true otherwise.
	 */
	static inline bool SafetyChecks(u32 command_len, int command_size, u32 reply_len, int reply_size = 0, u32 buf_size = MAX_IPC_SIZE - 1)
	{
		const bool res = ((command_len + command_size) > buf_size ||
					(reply_len + reply_size) >= MAX_IPC_RETURN_SIZE);
		if (res) [[unlikely]]
			return false;
		return true;
	}

public:
	// Whether the socket processing thread should stop executing/is stopped.
	std::atomic_bool m_end{ false };
	int m_slot;

	/* Initializers */
	PINEServer();
	virtual ~PINEServer();
	bool Initialize(int slot = PINE_DEFAULT_SLOT);
	void Deinitialize();

}; // class SocketIPC

