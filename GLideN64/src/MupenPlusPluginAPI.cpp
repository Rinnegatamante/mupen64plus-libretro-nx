#include "PluginAPI.h"
#include "Types.h"
#include "mupenplus/GLideN64_mupenplus.h"
#include "N64.h"
#include <cstddef>

// Defined in mupen64plus-core main.c
extern size_t rdram_size;

extern "C" {

EXPORT int CALL gln64RomOpen(void)
{
	if (rdram_size != 0)
		RDRAMSize = rdram_size - 1;
	else
		RDRAMSize = 0;

	return api().RomOpen();
}

EXPORT m64p_error CALL gln64PluginGetVersion(
	m64p_plugin_type * _PluginType,
	int * _PluginVersion,
	int * _APIVersion,
	const char ** _PluginNamePtr,
	int * _Capabilities
)
{
	return api().PluginGetVersion(_PluginType, _PluginVersion, _APIVersion, _PluginNamePtr, _Capabilities);
}

EXPORT m64p_error CALL gln64PluginStartup(
	m64p_dynlib_handle CoreLibHandle,
	void *Context,
	void (*DebugCallback)(void *, int, const char *)
)
{
	return api().PluginStartup(CoreLibHandle, Context, DebugCallback);
}

EXPORT m64p_error CALL gln64PluginShutdown(void)
{
	return api().PluginShutdown();
}

EXPORT void CALL gln64ReadScreen2(void *dest, int *width, int *height, int front)
{
	api().ReadScreen2(dest, width, height, front);
}

EXPORT void CALL gln64SetRenderingCallback(void (*callback)(int))
{
	api().SetRenderingCallback(callback);
}

EXPORT void CALL gln64ResizeVideoOutput(int width, int height)
{
	api().ResizeVideoOutput(width, height);
}

} // extern "C"
