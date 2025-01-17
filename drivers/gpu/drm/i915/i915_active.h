/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2019 Intel Corporation
 */

#ifndef _I915_ACTIVE_H_
#define _I915_ACTIVE_H_

#include <linux/lockdep.h>
#ifdef __FreeBSD__
#include <linux/list.h>
#endif

#include "i915_active_types.h"
#include "i915_request.h"

struct i915_request;
struct intel_engine_cs;
struct intel_timeline;

/*
 * We treat requests as fences. This is not be to confused with our
 * "fence registers" but pipeline synchronisation objects ala GL_ARB_sync.
 * We use the fences to synchronize access from the CPU with activity on the
 * GPU, for example, we should not rewrite an object's PTE whilst the GPU
 * is reading them. We also track fences at a higher level to provide
 * implicit synchronisation around GEM objects, e.g. set-domain will wait
 * for outstanding GPU rendering before marking the object ready for CPU
 * access, or a pageflip will wait until the GPU is complete before showing
 * the frame on the scanout.
 *
 * In order to use a fence, the object must track the fence it needs to
 * serialise with. For example, GEM objects want to track both read and
 * write access so that we can perform concurrent read operations between
 * the CPU and GPU engines, as well as waiting for all rendering to
 * complete, or waiting for the last GPU user of a "fence register". The
 * object then embeds a #i915_active_fence to track the most recent (in
 * retirement order) request relevant for the desired mode of access.
 * The #i915_active_fence is updated with i915_active_fence_set() to
 * track the most recent fence request, typically this is done as part of
 * i915_vma_move_to_active().
 *
 * When the #i915_active_fence completes (is retired), it will
 * signal its completion to the owner through a callback as well as mark
 * itself as idle (i915_active_fence.request == NULL). The owner
 * can then perform any action, such as delayed freeing of an active
 * resource including itself.
 */

void i915_active_noop(struct dma_fence *fence, struct dma_fence_cb *cb);

/**
 * __i915_active_fence_init - prepares the activity tracker for use
 * @active - the active tracker
 * @fence - initial fence to track, can be NULL
 * @func - a callback when then the tracker is retired (becomes idle),
 *         can be NULL
 *
 * i915_active_fence_init() prepares the embedded @active struct for use as
 * an activity tracker, that is for tracking the last known active fence
 * associated with it. When the last fence becomes idle, when it is retired
 * after completion, the optional callback @func is invoked.
 */
static inline void
__i915_active_fence_init(struct i915_active_fence *active,
			 struct mutex *lock,
			 void *fence,
			 dma_fence_func_t fn)
{
	RCU_INIT_POINTER(active->fence, fence);
	active->cb.func = fn ?: i915_active_noop;
#if IS_ENABLED(CONFIG_DRM_I915_DEBUG_GEM)
	active->lock = lock;
#endif
}

#define INIT_ACTIVE_FENCE(A, LOCK) \
	__i915_active_fence_init((A), (LOCK), NULL, NULL)

struct dma_fence *
__i915_active_fence_set(struct i915_active_fence *active,
			struct dma_fence *fence);

/**
 * i915_active_fence_set - updates the tracker to watch the current fence
 * @active - the active tracker
 * @rq - the request to watch
 *
 * i915_active_fence_set() watches the given @rq for completion. While
 * that @rq is busy, the @active reports busy. When that @rq is signaled
 * (or else retired) the @active tracker is updated to report idle.
 */
int __must_check
i915_active_fence_set(struct i915_active_fence *active,
		      struct i915_request *rq);
/**
 * i915_active_fence_get - return a reference to the active fence
 * @active - the active tracker
 *
 * i915_active_fence_get() returns a reference to the active fence,
 * or NULL if the active tracker is idle. The reference is obtained under RCU,
 * so no locking is required by the caller.
 *
 * The reference should be freed with dma_fence_put().
 */
static inline struct dma_fence *
i915_active_fence_get(struct i915_active_fence *active)
{
	struct dma_fence *fence;

	rcu_read_lock();
	fence = dma_fence_get_rcu_safe(&active->fence);
	rcu_read_unlock();

	return fence;
}

/**
 * i915_active_fence_isset - report whether the active tracker is assigned
 * @active - the active tracker
 *
 * i915_active_fence_isset() returns true if the active tracker is currently
 * assigned to a fence. Due to the lazy retiring, that fence may be idle
 * and this may report stale information.
 */
static inline bool
i915_active_fence_isset(const struct i915_active_fence *active)
{
	return rcu_access_pointer(active->fence);
}

static inline void
i915_active_fence_cb(struct dma_fence *fence, struct dma_fence_cb *cb)
{
	struct i915_active_fence *active =
		container_of(cb, typeof(*active), cb);

	RCU_INIT_POINTER(active->fence, NULL);
}

/*
 * GPU activity tracking
 *
 * Each set of commands submitted to the GPU compromises a single request that
 * signals a fence upon completion. struct i915_request combines the
 * command submission, scheduling and fence signaling roles. If we want to see
 * if a particular task is complete, we need to grab the fence (struct
 * i915_request) for that task and check or wait for it to be signaled. More
 * often though we want to track the status of a bunch of tasks, for example
 * to wait for the GPU to finish accessing some memory across a variety of
 * different command pipelines from different clients. We could choose to
 * track every single request associated with the task, but knowing that
 * each request belongs to an ordered timeline (later requests within a
 * timeline must wait for earlier requests), we need only track the
 * latest request in each timeline to determine the overall status of the
 * task.
 *
 * struct i915_active provides this tracking across timelines. It builds a
 * composite shared-fence, and is updated as new work is submitted to the task,
 * forming a snapshot of the current status. It should be embedded into the
 * different resources that need to track their associated GPU activity to
 * provide a callback when that GPU activity has ceased, or otherwise to
 * provide a serialisation point either for request submission or for CPU
 * synchronisation.
 */

void __i915_active_init(struct i915_active *ref,
			int (*active)(struct i915_active *ref),
			void (*retire)(struct i915_active *ref),
			struct lock_class_key *key);
#define i915_active_init(ref, active, retire) do {		\
	static struct lock_class_key __key;				\
									\
	__i915_active_init(ref, active, retire, &__key);		\
} while (0)

int i915_active_ref(struct i915_active *ref,
		    struct intel_timeline *tl,
		    struct dma_fence *fence);

static inline int
i915_active_add_request(struct i915_active *ref, struct i915_request *rq)
{
	return i915_active_ref(ref, i915_request_timeline(rq), &rq->fence);
}

void i915_active_set_exclusive(struct i915_active *ref, struct dma_fence *f);

static inline bool i915_active_has_exclusive(struct i915_active *ref)
{
	return rcu_access_pointer(ref->excl.fence);
}

int i915_active_wait(struct i915_active *ref);

int i915_request_await_active(struct i915_request *rq, struct i915_active *ref);

int i915_active_acquire(struct i915_active *ref);
bool i915_active_acquire_if_busy(struct i915_active *ref);
void i915_active_release(struct i915_active *ref);

static inline bool
i915_active_is_idle(const struct i915_active *ref)
{
	return !atomic_read(&ref->count);
}

#if IS_ENABLED(CONFIG_DRM_I915_DEBUG_GEM)
void i915_active_fini(struct i915_active *ref);
#else
static inline void i915_active_fini(struct i915_active *ref) { }
#endif

int i915_active_acquire_preallocate_barrier(struct i915_active *ref,
					    struct intel_engine_cs *engine);
void i915_active_acquire_barrier(struct i915_active *ref);
void i915_request_add_active_barriers(struct i915_request *rq);

void i915_active_print(struct i915_active *ref, struct drm_printer *m);

#endif /* _I915_ACTIVE_H_ */
