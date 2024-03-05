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

#include "PrecompiledHeader.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>

#if _WIN32
#define exit_process() (ExitProcess(0))
#define read_portable(a, b, c) (recv(a, (char*)b, c, 0))
#define write_portable(a, b, c) (send(a, (const char*)b, c, 0))
#define safe_close_portable(a) \
	do \
	{ \
		if ((a) >= 0) \
		{ \
			closesocket((a)); \
			(a) = INVALID_SOCKET; \
		} \
	} while (0)
#define bzero(b, len) (memset((b), '\0', (len)), (void)0)
#include <WinSock2.h>
#include <windows.h>
#else
#define exit_process() (kill(getpid(), SIGKILL))
#define read_portable(a, b, c) (read(a, b, c))
#define write_portable(a, b, c) (write(a, b, c))
#define safe_close_portable(a) \
	do \
	{ \
		if ((a) >= 0) \
		{ \
			close((a)); \
			(a) = -1; \
		} \
	} while (0)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include "MTGS.h"
#include "Common.h"
#include "Memory.h"
#include "pcsx2/Counters.h"
#include "pcsx2/Recording/InputRecordingControls.h"
#include "pcsx2/VMManager.h"
#include "svnrev.h"
#include "PINE.h"
#include "pcsx2/FrameStep.h"
#include "LayeredSettingsInterface.h"
#include <GS/Renderers/Common/GSTexture.h>
#include <GS/Renderers/Common/GSDevice.h>

#include "SIO/Pad/Pad.h"
#include "SIO/Pad/PadDualshock2.h"
#include "SIO/Sio.h"

#include "GS/Renderers/Common/GSRenderer.h"
#include <Host.h>
#include <INISettingsInterface.h>

extern u8 FRAME_BUFFER_COPY[];
extern bool g_eeRecExecuting;

int g_pine_slot = 0;
int g_disable_rendering = 0;
int reset = 0;
time_t g_pine_last_recv_seconds;
time_t g_pine_last_connection;

struct
{
	u8 interop_recv_buf[MAX_IPC_SIZE];
	u8 interop_send_buf[MAX_IPC_RETURN_SIZE];
	int recv_len;
	int send_len;
} interop_state;

void SetPad(int port, int slot, u8* buf);
uptr vtlb_getTblPtr(u32 addr);

PINEServer::PINEServer() {}

PINEServer::~PINEServer()
{
	Deinitialize();
}

bool PINEServer::Initialize(int slot)
{
	m_end.store(false, std::memory_order_release);
	m_slot = slot;
#ifdef _WIN32
	WSADATA wsa;
	struct sockaddr_in server;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		DevCon.WriteLn(Color_Red, "PINE: Cannot initialize winsock! Shutting down...");
		Deinitialize();
		return false;
	}

	m_sock = socket(AF_INET, SOCK_STREAM, 0);
	if ((m_sock == INVALID_SOCKET) || slot > 65536)
	{
		DevCon.WriteLn(Color_Red, "PINE: Cannot open socket! Shutting down...");
		Deinitialize();
		return false;
	}

	// yes very good windows s/sun/sin/g sure is fine
	server.sin_family = AF_INET;
	// localhost only
	server.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // localhost only
	server.sin_port = htons(slot);

	if (bind(m_sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
	{
		DevCon.WriteLn(Color_Red, "PINE: Error while binding to socket! Shutting down...");
		Deinitialize();
		return false;
	}

#else
	char* runtime_dir = nullptr;
#ifdef __APPLE__
	runtime_dir = std::getenv("TMPDIR");
#else
	runtime_dir = std::getenv("XDG_RUNTIME_DIR");
#endif
	// fallback in case macOS or other OSes don't implement the XDG base
	// spec
	if (runtime_dir == nullptr)
		m_socket_name = "/tmp/" PINE_EMULATOR_NAME ".sock";
	else
	{
		m_socket_name = runtime_dir;
		m_socket_name += "/" PINE_EMULATOR_NAME ".sock";
	}

	if (slot != PINE_DEFAULT_SLOT)
		m_socket_name += "." + std::to_string(slot);

	struct sockaddr_un server;

	m_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (m_sock < 0)
	{
		DevCon.WriteLn(Color_Red, "PINE: Cannot open socket! Shutting down...");
		Deinitialize();
		return false;
	}
	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, m_socket_name.c_str());

	// we unlink the socket so that when releasing this thread the socket gets
	// freed even if we didn't close correctly the loop
	unlink(m_socket_name.c_str());
	if (bind(m_sock, (struct sockaddr*)&server, sizeof(struct sockaddr_un)))
	{
		DevCon.WriteLn(Color_Red, "PINE: Error while binding to socket! Shutting down...");
		Deinitialize();
		return false;
	}
#endif

	// maximum queue of 4096 commands before refusing, approximated to the
	// nearest legal value. We do not use SOMAXCONN as windows have this idea
	// that a "reasonable" value is 5, which is not.
	if (listen(m_sock, 4096))
	{
		DevCon.WriteLn(Color_Red, "PINE: Cannot listen for connections! Shutting down...");
		Deinitialize();
		return false;
	}

	// we allocate once buffers to not have to do mallocs for each IPC
	// request, as malloc is expansive when we optimize for µs.
	m_ret_buffer.resize(MAX_IPC_RETURN_SIZE);
	m_ipc_buffer.resize(MAX_IPC_SIZE);
	m_mem_ret_buffer.resize(MAX_IPC_RETURN_SIZE);

	// reset recv time
	g_pine_last_recv_seconds = time(NULL);

	// we start the thread
	m_thread = std::thread(&PINEServer::MainLoop, this);

	return true;
}

std::vector<u8>& PINEServer::MakeOkIPC(std::vector<u8>& ret_buffer, uint32_t size = 5)
{
	ToResultVector<uint32_t>(ret_buffer, size, 0);
	ret_buffer[4] = IPC_OK;
	return ret_buffer;
}

std::vector<u8>& PINEServer::MakeFailIPC(std::vector<u8>& ret_buffer, uint32_t size = 5)
{
	ToResultVector<uint32_t>(ret_buffer, size, 0);
	ret_buffer[4] = IPC_FAIL;
	return ret_buffer;
}

bool PINEServer::AcceptClient()
{
	m_msgsock = accept(m_sock, 0, 0);
	if (m_msgsock >= 0)
	{
		// Gross C-style cast, but SOCKET is a handle on Windows.
		Console.WriteLn("PINE: New client with FD %d connected.", (int)m_msgsock);
		return true;
	}

	// everything else is non recoverable in our scope
	// we also mark as recoverable socket errors where it would block a
	// non blocking socket, even though our socket is blocking, in case
	// we ever have to implement a non blocking socket.
#ifdef _WIN32
	int errno_w = WSAGetLastError();
	if (!(errno_w == WSAECONNRESET || errno_w == WSAEINTR || errno_w == WSAEINPROGRESS || errno_w == WSAEMFILE || errno_w == WSAEWOULDBLOCK) && m_sock != INVALID_SOCKET)
	{
#else
	if (!(errno == ECONNABORTED || errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
	{
#endif
		DevCon.WriteLn("PINE: An unrecoverable error happened! Shutting down...");
	}

	return false;
}

void PINEServer::IpcLoop()
{
	const std::span<u8> ipc_buffer_span(interop_state.interop_recv_buf);

	int len = interop_state.recv_len;
	if (len > 0)
	{
		interop_state.recv_len = 0;
		interop_state.send_len = 0;
		PINEServer::IPCBuffer res;

		// we remove 4 bytes to get the message size out of the IPC command
		// size in ParseCommand.
		// also, if we got a failed command, let's reset the state so we don't
		// end up deadlocking by getting out of sync, eg when a client
		// disconnects
		res = ParseCommand(ipc_buffer_span.subspan(4), m_mem_ret_buffer, (u32)len - 4);

		// move response into send buf
		memcpy((u8*)interop_state.interop_send_buf, res.buffer.data(), res.size);
		interop_state.send_len = res.size;
	}
}

void PINEServer::MainLoop()
{
	Console.WriteLn("PINE: Socket ready.");
	while (!m_end.load(std::memory_order_acquire))
	{
		if (!AcceptClient())
			continue;

		g_pine_last_connection = time(NULL);
		ClientLoop();
		g_pine_last_connection = 0;

		Console.WriteLn("PINE: Client disconnected.");
		safe_close_portable(m_msgsock);
	}

	DevCon.WriteLn("PINE: exiting main loop...");
}

void PINEServer::ClientLoop()
{
	while (!m_end.load(std::memory_order_acquire))
	{
		// either int or ssize_t depending on the platform, so we have to
		// use a bunch of auto
		auto receive_length = 0;
		auto end_length = 4;
		const std::span<u8> ipc_buffer_span(m_ipc_buffer);

		// while we haven't received the entire packet, maybe due to
		// socket datagram splittage, we continue to read
		while (receive_length < end_length)
		{
			const auto tmp_length = read_portable(m_msgsock, &ipc_buffer_span[receive_length], MAX_IPC_SIZE - receive_length);

			// we recreate the socket if an error happens
			if (tmp_length <= 0)
			{
				receive_length = 0;
				exit_process();
				DevCon.WriteLn("PINE: Cannot recieve request.. restarting socket...");
				return;
			}

			receive_length += tmp_length;

			// if we got at least the final size then update
			if (end_length == 4 && receive_length >= 4)
			{
				end_length = FromSpan<u32>(ipc_buffer_span, 0);
				// we'd like to avoid a client trying to do OOB
				if (end_length > MAX_IPC_SIZE || end_length < 4)
				{
					receive_length = 0;
					break;
				}
			}
		}
		PINEServer::IPCBuffer res;

		// we remove 4 bytes to get the message size out of the IPC command
		// size in ParseCommand.
		// also, if we got a failed command, let's reset the state so we don't
		// end up deadlocking by getting out of sync, eg when a client
		// disconnects
		if (receive_length != 0)
		{
			g_pine_last_recv_seconds = time(NULL);
			res = ParseCommand(ipc_buffer_span.subspan(4), m_ret_buffer, (u32)end_length - 4);

			// if we cannot send back our answer restart the socket
			if (write_portable(m_msgsock, res.buffer.data(), res.size) < 0)
			{
				exit_process();
				DevCon.WriteLn("PINE: Cannot send response.. restarting socket...");
				return;
			}
		}

		if (reset)
		{
			reset = 0;
			return;
		}
	}

	DevCon.WriteLn("PINE: exiting socket loop...");
}

void PINEServer::Deinitialize()
{
	m_end.store(true, std::memory_order_release);

#ifdef _WIN32
	WSACleanup();
#else
	unlink(m_socket_name.c_str());
#endif
	safe_close_portable(m_sock);
	safe_close_portable(m_msgsock);

	if (m_thread.joinable())
	{
		m_thread.join();
	}
}

PINEServer::IPCBuffer PINEServer::ParseCommand(std::span<u8> buf, std::vector<u8>& ret_buffer, u32 buf_size)
{
	u32 ret_cnt = 5;
	u32 buf_cnt = 0;

	while (buf_cnt < buf_size)
	{
		if (!SafetyChecks(buf_cnt, 1, ret_cnt, 0, buf_size))
			return IPCBuffer{ 5, MakeFailIPC(ret_buffer) };
		buf_cnt++;

		IPCCommand cmd = (IPCCommand)buf[buf_cnt - 1];

		// example IPC messages: MsgRead/Write
		// refer to the client doc for more info on the format
		//         IPC Message event (1 byte)
		//         |  Memory address (4 byte)
		//         |  |           argument (VLE)
		//         |  |           |
		// format: XX YY YY YY YY ZZ ZZ ZZ ZZ
		//        reply code: 00 = OK, FF = NOT OK
		//        |  return value (VLE)
		//        |  |
		// reply: XX ZZ ZZ ZZ ZZ
		switch (cmd)
		{
			case MsgRead8:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 4, ret_cnt, 1, buf_size))
					goto error;
				const u32 a = FromSpan<u32>(buf, buf_cnt);
				const u8 res = memRead8(a);
				ToResultVector(ret_buffer, res, ret_cnt);
				ret_cnt += 1;
				buf_cnt += 4;
				break;
			}
		case MsgRead16:
			{
				if (!VMManager::HasValidVM())
					goto error;
			if (!SafetyChecks(buf_cnt, 4, ret_cnt, 2, buf_size))
				goto error;
			const u32 a = FromSpan<u32>(buf, buf_cnt);
			const u16 res = memRead16(a);
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 2;
			buf_cnt += 4;
			break;
		}
		case MsgRead32:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 4, ret_cnt, 4, buf_size))
					goto error;
				const u32 a = FromSpan<u32>(buf, buf_cnt);
				const u32 res = memRead32(a);
				ToResultVector(ret_buffer, res, ret_cnt);
				ret_cnt += 4;
				buf_cnt += 4;
				break;
			}
			case MsgRead64:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 4, ret_cnt, 8, buf_size))
					goto error;
				const u32 a = FromSpan<u32>(buf, buf_cnt);
				const u64 res = memRead64(a);
				ToResultVector(ret_buffer, res, ret_cnt);
				ret_cnt += 8;
				buf_cnt += 4;
				break;
			}
			case MsgWrite8:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 1 + 4, ret_cnt, 0, buf_size))
					goto error;
				const u32 a = FromSpan<u32>(buf, buf_cnt);
				memWrite8(a, FromSpan<u8>(buf, buf_cnt + 4));
				buf_cnt += 5;
				break;
			}
			case MsgWrite16:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 2 + 4, ret_cnt, 0, buf_size))
					goto error;
				const u32 a = FromSpan<u32>(buf, buf_cnt);
				memWrite16(a, FromSpan<u16>(buf, buf_cnt + 4));
				buf_cnt += 6;
				break;
			}
			case MsgWrite32:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 4 + 4, ret_cnt, 0, buf_size))
					goto error;
				const u32 a = FromSpan<u32>(buf, buf_cnt);
				memWrite32(a, FromSpan<u32>(buf, buf_cnt + 4));
				buf_cnt += 8;
				break;
			}
			case MsgWrite64:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 8 + 4, ret_cnt, 0, buf_size))
					goto error;
				const u32 a = FromSpan<u32>(buf, buf_cnt);
				memWrite64(a, FromSpan<u64>(buf, buf_cnt + 4));
				buf_cnt += 12;
				break;
			}
			case MsgVersion:
			{
				if (!VMManager::HasValidVM())
					goto error;

				static constexpr const char* version = "PCSX2 " GIT_REV;
				static constexpr u32 size = sizeof(version) + 1;
				if (!SafetyChecks(buf_cnt, 0, ret_cnt, size + 4, buf_size)) [[unlikely]]
					goto error;
				ToResultVector(ret_buffer, size, ret_cnt);
				ret_cnt += 4;
				memcpy(&ret_buffer[ret_cnt], version, size);
				ret_cnt += size;
				break;
			}
			case MsgSaveState:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 1, ret_cnt, 0, buf_size))
					goto error;
				VMManager::SaveStateToSlot(FromSpan<u8>(buf, buf_cnt));
				buf_cnt += 1;
				break;
			}
			case MsgLoadState:
			{
				if (!VMManager::HasValidVM())
					goto error;
				if (!SafetyChecks(buf_cnt, 1, ret_cnt, 0, buf_size))
					goto error;
				VMManager::LoadStateFromSlot(FromSpan<u8>(buf, buf_cnt));
				buf_cnt += 1;
				break;
			}
			case MsgTitle:
			{
				if (!VMManager::HasValidVM())
					goto error;
				const std::string gameName = VMManager::GetTitle(false);
				const u32 size = gameName.size() + 1;
				if (!SafetyChecks(buf_cnt, 0, ret_cnt, size + 4, buf_size))
					goto error;
				ToResultVector(ret_buffer, size, ret_cnt);
				ret_cnt += 4;
				memcpy(&ret_buffer[ret_cnt], gameName.c_str(), size);
				ret_cnt += size;
				break;
			}
			case MsgID:
			{
				if (!VMManager::HasValidVM())
					goto error;
				const std::string gameSerial = VMManager::GetDiscSerial();
				const u32 size = gameSerial.size() + 1;
				if (!SafetyChecks(buf_cnt, 0, ret_cnt, size + 4, buf_size))
					goto error;
				ToResultVector(ret_buffer, size, ret_cnt);
				ret_cnt += 4;
				memcpy(&ret_buffer[ret_cnt], gameSerial.c_str(), size);
				ret_cnt += size;
				break;
			}
			case MsgUUID:
			{
				if (!VMManager::HasValidVM())
					goto error;
				const std::string crc = fmt::format("{:08x}", VMManager::GetDiscCRC());
				const u32 size = crc.size() + 1;
				if (!SafetyChecks(buf_cnt, 0, ret_cnt, size + 4, buf_size))
					goto error;
				ToResultVector(ret_buffer, size, ret_cnt);
				ret_cnt += 4;
				memcpy(&ret_buffer[ret_cnt], crc.c_str(), size);
				ret_cnt += size;
				break;
			}
			case MsgGameVersion:
			{
				if (!VMManager::HasValidVM())
					goto error;

				const std::string ElfVersion = VMManager::GetDiscVersion();
				const u32 size = ElfVersion.size() + 1;
				if (!SafetyChecks(buf_cnt, 0, ret_cnt, size + 4, buf_size))
					goto error;
				ToResultVector(ret_buffer, size, ret_cnt);
				ret_cnt += 4;
				memcpy(&ret_buffer[ret_cnt], ElfVersion.c_str(), size);
				ret_cnt += size;
				break;
			}
		case MsgStatus:
		{
			if (!SafetyChecks(buf_cnt, 0, ret_cnt, 8, buf_size))
				goto error;
			EmuStatus status;

			if (VMManager::HasValidVM())
			{
				if (g_FrameStep.IsPaused())
					status = Paused;
				else
				{
					switch (VMManager::GetState())
					{
						case VMState::Running:
							status = EmuStatus::Running;
							break;
						case VMState::Paused:
							status = EmuStatus::Paused;
							break;
						default:
							status = EmuStatus::Shutdown;
							break;
					}
				}
			}
			else
			{
				status = Shutdown;
			}

			ToResultVector(ret_buffer, status, ret_cnt);
			ToResultVector(ret_buffer, g_FrameCount, ret_cnt + 4);
			ToResultVector(ret_buffer, g_eeRecExecuting, ret_cnt + 8);
			ret_cnt += 9;
			break;
		}

		case MsgReadN:
		{
			if (!VMManager::HasValidVM())
				goto error;
			if (!SafetyChecks(buf_cnt, 6, ret_cnt, 1, buf_size))
				goto error;

			const u32 a = FromSpan<u32>(buf, buf_cnt);
			const u16 l = FromSpan<u16>(buf, buf_cnt + 4);
			if (!SafetyChecks(buf_cnt, 6, ret_cnt, l, buf_size))
				goto error;
			if (!vtlb_memSafeReadBytes(a, reinterpret_cast<mem8_t*>(&ret_buffer[ret_cnt]), (u32)l))
				goto error;
			//if (!vtlb_ramRead(a, reinterpret_cast<mem8_t*>(&ret_buffer[ret_cnt]), (u32)l))
			//	goto error;
			ret_cnt += l;
			buf_cnt += 6;
			break;
		}
		case MsgWriteN:
		{
			if (!VMManager::HasValidVM())
				goto error;
			if (!SafetyChecks(buf_cnt, 6, ret_cnt, 1, buf_size))
				goto error;

			const u32 a = FromSpan<u32>(buf, buf_cnt);
			const u32 c = FromSpan<u16>(buf, buf_cnt + 4);
			if (!SafetyChecks(buf_cnt, c + 6, ret_cnt, 0, buf_size))
				goto error;
			buf_cnt += 6;
			vtlb_memSafeWriteBytes(a, reinterpret_cast<mem8_t*>(&buf[buf_cnt]), (u32)c);
			//if (!vtlb_ramWrite(a, reinterpret_cast<mem8_t*>(&buf[buf_cnt]), (u32)c))
			//	goto error;
			buf_cnt += c;
			u8 res = 1;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 1;
			break;
		}
		case MsgFrameAdvance:
		{
			if (!VMManager::HasValidVM())
				goto error;
			if (!SafetyChecks(buf_cnt, 0, ret_cnt, 1, buf_size))
				goto error;
			g_FrameStep.FrameAdvance();
			u8 res = 1;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 1;
			break;
		}
		case MsgSetDynamicSetting:
		{
			if (!SafetyChecks(buf_cnt, 1, ret_cnt, 1, buf_size))
				goto error;

			// get args
			const enum DynamicSettingId settingId = (enum DynamicSettingId)FromSpan<u8>(buf, buf_cnt);

			switch (settingId)
			{
				case DynamicSettingFrameSleepWait:
				{
					const u8 value = FromSpan<u8>(buf, buf_cnt + 1);
					g_FrameStep.SetSleepWait(value != 0);
					buf_cnt += 1;
					break;
				}
				case DynamicSettingDisableRendering:
				{
					const u8 value = FromSpan<u8>(buf, buf_cnt + 1);
					g_disable_rendering = value != 0;

					buf_cnt += 1;
					break;
				}
				case DynamicSettingReloadConfig:
				{
					LayeredSettingsInterface* lsi = (LayeredSettingsInterface*)Host::GetSettingsInterface();
					INISettingsInterface* si = (INISettingsInterface*)lsi->GetLayer(LayeredSettingsInterface::LAYER_BASE);
					if (si)
					{
						si->Clear();
						si->Load();
					}
					VMManager::ApplySettings();
					break;
				}
				case DynamicSettingResetSocket:
				{
					DevCon.WriteLn("PINE: Recv DynamicSettingResetSocket.. restarting socket...");
					reset = 1;
					break;
				}
				default:
				{
					break;
				}
			}

			buf_cnt += 1;

			u8 res = 1;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 1;
			break;
		}
		case MsgResume:
		{
			if (!VMManager::HasValidVM())
				goto error;
			if (!SafetyChecks(buf_cnt, 0, ret_cnt, 1, buf_size))
				goto error;
			g_FrameStep.Resume();
			u8 res = 1;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 1;
			break;
		}
		case MsgPause:
		{
			if (!VMManager::HasValidVM())
				goto error;
			if (!SafetyChecks(buf_cnt, 0, ret_cnt, 1, buf_size))
				goto error;
			g_FrameStep.Pause();
			u8 res = 1;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 1;
			break;
		}
		case MsgRestart:
		{
			if (!VMManager::HasValidVM())
				goto error;
			//g_Conf->EmuOptions.UseBOOT2Injection = true;
			VMManager::Reset();
			//CoreThread.ResetQuick();
			//CoreThread.Resume();
			g_FrameStep.Resume();

			u8 res = 1;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 1;
			break;
		}
		case MsgStop:
		{
			if (!SafetyChecks(buf_cnt, 0, ret_cnt, 1, buf_size))
				goto error;
			//g_Conf->EmuOptions.UseBOOT2Injection = true;
			//CoreThread.ResetQuick();


			VMManager::Shutdown(false);

			//if (GSFrame* gsframe = wxGetApp().GetGsFramePtr())
			//	gsframe->Show(false);

			//CoreThread.Resume();
			g_FrameStep.Resume();

			u8 res = 1;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 1;
			break;
		}
		case MsgGetFrameBuffer:
		{
			int bitCount = 512 * 448 * 4;
			if (!VMManager::HasValidVM())
				goto error;
			if (!SafetyChecks(buf_cnt, 0, ret_cnt, bitCount, buf_size))
				goto error;

			memcpy(&ret_buffer[ret_cnt], FRAME_BUFFER_COPY, bitCount);
			ret_cnt += bitCount;
			break;
		}
		case MsgSetPad:
		{
			if (!VMManager::HasValidVM())
				goto error;
			if (!SafetyChecks(buf_cnt, 36, ret_cnt, 1, buf_size))
				goto error;

			// get args
			const u16 port = FromSpan<u16>(buf, buf_cnt);
			const u16 slot = FromSpan<u16>(buf, buf_cnt + 2);
			buf_cnt += 4;

			// set pad
			SetPad(port, slot, (u8*)&buf[buf_cnt]);

			buf_cnt += 32;
			u8 res = 1;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 1;
			break;
		}
		case MsgGetVmPtr:
		{
			//if (!VMManager::HasValidVM())
			//	goto error;
			if (!SafetyChecks(buf_cnt, 0, ret_cnt, 8*5, buf_size))
				goto error;

			uptr res = 0; 
			if (VMManager::HasValidVM())
				res = vtlb_getTblPtr(0x100000) - 0x100000;

			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 8;

			res = (uptr)&g_FrameCount;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 8;

			res = (uptr)&g_eeRecExecuting;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 8;

			res = (uptr)&interop_state;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 8;

			res = (uptr)&FRAME_BUFFER_COPY;
			ToResultVector(ret_buffer, res, ret_cnt);
			ret_cnt += 8;
			break;
		}

		default:
		{
		error:
			DevCon.WriteLn(Color_Red, "PINE: Command failed %d", cmd);
			return IPCBuffer{ 5, MakeFailIPC(ret_buffer) };
		}
		}
	}
	return IPCBuffer{ (int)ret_cnt, MakeOkIPC(ret_buffer, ret_cnt) };
}

void SetPad(int port, int slot, u8* buf)
{
	PadBase* pad = Pad::GetPad(port);
	pad->SetRawAnalogs(std::tuple<u8, u8>(buf[6], buf[7]), std::tuple<u8, u8>(buf[4], buf[5]));

	pad->Set(PadDualshock2::Inputs::PAD_RIGHT, buf[8]);
	pad->Set(PadDualshock2::Inputs::PAD_LEFT, buf[9]);
	pad->Set(PadDualshock2::Inputs::PAD_UP, buf[10]);
	pad->Set(PadDualshock2::Inputs::PAD_DOWN, buf[11]);
	pad->Set(PadDualshock2::Inputs::PAD_START, buf[20]);
	pad->Set(PadDualshock2::Inputs::PAD_SELECT, buf[21]);
	pad->Set(PadDualshock2::Inputs::PAD_R3, buf[23]);
	pad->Set(PadDualshock2::Inputs::PAD_L3, buf[22]);

	pad->Set(PadDualshock2::Inputs::PAD_SQUARE, buf[15]);
	pad->Set(PadDualshock2::Inputs::PAD_CROSS, buf[14]);
	pad->Set(PadDualshock2::Inputs::PAD_CIRCLE, buf[13]);
	pad->Set(PadDualshock2::Inputs::PAD_TRIANGLE, buf[12]);

	pad->Set(PadDualshock2::Inputs::PAD_R1, buf[17]);
	pad->Set(PadDualshock2::Inputs::PAD_L1, buf[16]);
	pad->Set(PadDualshock2::Inputs::PAD_R2, buf[19]);
	pad->Set(PadDualshock2::Inputs::PAD_L2, buf[18]);
}
