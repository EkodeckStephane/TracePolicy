# Preliminary cross-OS attempt

This directory preserves an incomplete preliminary campaign: five of the planned thirty runs completed. The sixth run, `restart_00`, stopped because the launcher waited two seconds for an event checkpoint although the cross-OS schedule started after 2.5 seconds. No algorithm verdict was obtained for that restart run, and the remaining 24 runs were not executed.

The next campaign changes only the restart synchronization: wait until the later of two seconds after the current time and two seconds after the scheduled start, and require at least one recorded event before stopping the coordinator. The frozen revised implementation and the complete replacement campaign are in `../distributed_live_crossos_corrected`. This preliminary directory is not the final 30-run evidence.
