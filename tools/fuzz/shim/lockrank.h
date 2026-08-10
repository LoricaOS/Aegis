#ifndef SHIM_LOCKRANK_H
#define SHIM_LOCKRANK_H
/* Lock-order accounting compiles to nothing without AEGIS_LOCK_DEBUG. */
static inline void lockrank_acquire(const void *l) { (void)l; }
static inline void lockrank_release(const void *l) { (void)l; }
#endif
