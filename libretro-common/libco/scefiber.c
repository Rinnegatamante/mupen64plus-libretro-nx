/*
  libco.win (2016-09-06)
  authors: frangarcj
  license: public domain
*/

#define LIBCO_C
#include <libco.h>
#include <stdlib.h>
#include <vitasdk.h>

#ifdef __cplusplus
extern "C" {
#endif

static thread_local cothread_t co_active_ = 0;

static int co_inited = 0;

/* Forward declarations */
int32_t sceFiberReturnToThread(uint32_t argOnReturn, uint32_t* argOnRun);

static void co_thunk(uint32_t argOnInitialize, uint32_t argOnRun)
{
	((void (*)(void))argOnInitialize)();
}

cothread_t co_active(void)
{
	return co_active_;
}

cothread_t co_create(unsigned int heapsize, void (*coentry)(void))
{
	int ret;
	SceFiber *tail_fiber = (SceFiber *)malloc(sizeof(SceFiber));
	char *m_ctxbuf = (char *)malloc(sizeof(char) * heapsize);
	if (!co_inited)
	{
		sceSysmoduleLoadModule(SCE_SYSMODULE_FIBER);
		co_inited = 1;
	}

	/* _sceFiberInitializeImpl */
	if ((ret = _sceFiberInitializeImpl(tail_fiber, "tailFiber", co_thunk, (uint32_t)coentry, (void*)m_ctxbuf, heapsize, NULL)) == 0) {
		return (cothread_t)tail_fiber;
	}

	return (cothread_t)ret;
}

void co_delete(cothread_t cothread)
{
	if (cothread != (cothread_t)0)
		sceFiberFinalize((SceFiber*)cothread);
}

void co_switch(cothread_t cothread)
{
	uint32_t argOnReturn  = 0;
	if (cothread == (cothread_t)0)
	{
		co_active_ = cothread;
		sceFiberReturnToThread(0, NULL);
	}
	else
	{
		SceFiber* theFiber = (SceFiber*)cothread;
		if (co_active_ == (cothread_t)0) {
			co_active_ = cothread;
			sceFiberRun(theFiber, 0, &argOnReturn);
		} else {
			co_active_ = cothread;
			sceFiberSwitch(theFiber, 0, &argOnReturn); 
		}
	}
}

#ifdef __cplusplus
}
#endif
