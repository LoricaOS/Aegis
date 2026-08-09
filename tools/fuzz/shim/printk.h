#ifndef SHIM_PRINTK_H
#define SHIM_PRINTK_H
/* host shim: kernel printk -> nothing (keeps fuzz output clean & fast) */
static inline void printk(const char *fmt, ...) { (void)fmt; }
#define panic(...) __builtin_trap()
#endif
