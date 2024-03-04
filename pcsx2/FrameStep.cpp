#include "PrecompiledHeader.h"

#include "Counters.h"
#include "DebugTools/Debug.h"
#include "MemoryTypes.h"
#include "FrameStep.h"
#include "VMManager.h"
#include "PINE.h"
#include "Host.h"
#include <common/Threading.h>

FrameStep g_FrameStep;
extern PINEServer s_pine_server;

void FrameStep::CheckPauseStatus()
{
	frame_advance_frame_counter++;
	if (frameAdvancing && frame_advance_frame_counter >= frames_per_frame_advance)
	{
		pauseEmulation = true;
		resumeEmulation = false;
		frameAdvancing = false;
	}
}

void FrameStep::HandlePausing()
{
	s_pine_server.IpcLoop();
	if (pauseEmulation && VMManager::GetState() == VMState::Running)
	{
		emulationCurrentlyPaused = true;
		while (!resumeEmulation) {
			if (sleepWhileWaiting) { Threading::Sleep(1); } // sleep until resumeEmulation is true
			else { Threading::Sleep(0); }
			//else Threading::Sleep(1); // sleep until resumeEmulation is true
			// otherwise just eat cycle until we can
			//volatile int i = 0;
			//i++;

			//DevCon.WriteLn("waiting for frame advance... %d %d %d\n", resumeEmulation, frameAdvancing, frame_advance_frame_counter);
			s_pine_server.IpcLoop();
		}
		resumeEmulation = false;
		emulationCurrentlyPaused = false;
	}
}

void FrameStep::FrameAdvance()
{
	frameAdvancing = true;
	frame_advance_frame_counter = 0;
	Resume();
}

bool FrameStep::IsFrameAdvancing()
{
	return frameAdvancing;
}

bool FrameStep::IsPaused()
{
	return emulationCurrentlyPaused;
}

void FrameStep::Pause()
{
	pauseEmulation = true;
	resumeEmulation = false;
}

void FrameStep::Resume()
{
	pauseEmulation = false;
	resumeEmulation = true;
}

void FrameStep::SetSleepWait(bool sleep)
{
	sleepWhileWaiting = sleep;
}
