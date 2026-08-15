#!/usr/bin/env python3
"""Small source-level guard for the two scheduler policies and SMP wake path."""

from pathlib import Path


root = Path(__file__).resolve().parents[1]
sched = (root / "kernel/sched/sched.c").read_text()
arm_timer = (root / "kernel/arch/arm64/timer.c").read_text()
identity = (root / "kernel/syscall/sys_identity.c").read_text()

assert "static enum sched_policy_id s_sched_policy = SCHED_POLICY_FAIR" in sched
assert 'cmdline_sched_is("rr")' in sched
assert "s_fair_rq[MAX_CPUS]" in sched
assert "task->sched_vruntime += now - task->sched_exec_start" in sched
assert "was_running &&" in sched and "task->on_cpu >= 0" in sched
assert "if (!rq->head && task->sched_vruntime > rq->min_vruntime)" in sched
assert "if (cpu == 0)" in arm_timer
assert "if (g_ap_sched_enabled)" in identity
assert "g_ap_online[cpu] && g_percpu[cpu].idle_task" in identity

print("scheduler policy checks: ok")
