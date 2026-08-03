#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KernelSU 5.4 kernel compatibility patch script
Run this inside the kernel source root (where drivers/kernelsu/ exists), e.g.:
    cd kernel
    python3 patch_54.py
It adds fallbacks for APIs missing in kernel 5.4 and stubs 6.x-only features.
"""
import os
STRN = """
/* 5.4 compat: strncpy_from_user_nofault fallback */
#ifndef HAVE_STRNCPY_FROM_USER_NOFAULT
static long strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
    long res;
    if (unlikely(count <= 0))
        return 0;
    pagefault_disable();
    res = strncpy_from_user(dst, unsafe_addr, count);
    pagefault_enable();
    return res;
}
#endif
"""
CPY = """
/* 5.4 compat: copy_to_kernel_nofault fallback */
#ifndef HAVE_COPY_TO_KERNEL_NOFAULT
static inline long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
{
    pagefault_disable();
    memcpy(dst, src, size);
    pagefault_enable();
    return 0;
}
#endif
"""
CFU = """
/* 5.4 compat: copy_from_user_nofault fallback */
#ifndef HAVE_COPY_FROM_USER_NOFAULT
static inline long copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
    long ret;
    if (unlikely(!access_ok(src, size)))
        return -EFAULT;
    pagefault_disable();
    ret = copy_from_user(dst, src, size);
    pagefault_enable();
    return ret;
}
#endif
"""
CTU = """
/* 5.4 compat: copy_to_user_nofault fallback */
#ifndef HAVE_COPY_TO_USER_NOFAULT
static inline long copy_to_user_nofault(void __user *dst, const void *src, size_t size)
{
    long ret;
    if (unlikely(!access_ok(dst, size)))
        return -EFAULT;
    pagefault_disable();
    ret = copy_to_user(dst, src, size);
    pagefault_enable();
    return ret;
}
#endif
"""
SEC = """
/* 5.4 compat: security_inode_init_security_anon fallback */
#ifndef HAVE_SECURITY_INODE_INIT_SECURITY_ANON
static inline int security_inode_init_security_anon(struct inode *inode, const struct qstr *name, const struct inode *context_inode)
{
    return 0;
}
#endif
"""
PATCHES = [('strncpy_from_user_nofault', 'strncpy_from_user_nofault fallback', STRN),
           ('copy_to_kernel_nofault', 'copy_to_kernel_nofault fallback', CPY),
           ('copy_from_user_nofault', 'copy_from_user_nofault fallback', CFU),
           ('copy_to_user_nofault', 'copy_to_user_nofault fallback', CTU),
           ('security_inode_init_security_anon', 'security_inode_init_security_anon fallback', SEC)]
for root, dirs, files in os.walk('drivers/kernelsu'):
    for fn in files:
        if not fn.endswith('.c'):
            continue
        fp = os.path.join(root, fn)
        src = open(fp).read()
        need_uaccess = any(k in src for k, _, _ in PATCHES) and '#include <linux/uaccess.h>' not in src
        for key, marker, code in PATCHES:
            if key in src and marker not in src:
                lines = src.split('\n')
                last_inc = -1
                for idx, ln in enumerate(lines):
                    if ln.startswith('#include'):
                        last_inc = idx
                if last_inc < 0:
                    continue
                ins = [code]
                if need_uaccess:
                    ins = ['#include <linux/uaccess.h>', code]
                    need_uaccess = False
                for extra in reversed(ins):
                    lines.insert(last_inc + 1, extra)
                src = '\n'.join(lines)
                open(fp, 'w').write(src)
                print('patched', fp, key)
# seccomp cache is 6.x-only: stub it out on older kernels
import subprocess
r = subprocess.run('grep -rl SECCOMP_ARCH_NATIVE_NR arch include 2>/dev/null', shell=True, capture_output=True, text=True)
sp = 'drivers/kernelsu/infra/seccomp_cache.c'
if os.path.exists(sp) and not r.stdout.strip():
    open(sp, 'w').write('''#include <linux/version.h>
#include "infra/seccomp_cache.h"

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
}
''')
    print('seccomp_cache stubbed for 5.4')
# pkg_observer uses 5.14+ fsnotify API: stub it out on older kernels
r2 = subprocess.run('grep -c handle_inode_event include/linux/fsnotify_backend.h 2>/dev/null', shell=True, capture_output=True, text=True)
pp = 'drivers/kernelsu/manager/pkg_observer.c'
if os.path.exists(pp) and r2.stdout.strip() == '0':
    open(pp, 'w').write('''#include <linux/version.h>
#include "manager/throne_tracker.h"

int ksu_observer_init(void)
{
    return 0;
}

void __exit ksu_observer_exit(void)
{
}
''')
    print('pkg_observer stubbed for 5.4')
# allowlist.c uses TWA_RESUME (5.7+) and put_task_struct: fix for 5.4
al = 'drivers/kernelsu/policy/allowlist.c'
if os.path.exists(al):
    src = open(al).read()
    changed = False
    if '#include <linux/sched/task.h>' not in src:
        src = src.replace('#include <linux/sched/task.h>', '')
        lines = src.split('\n')
        last_inc = -1
        for idx, ln in enumerate(lines):
            if ln.startswith('#include'):
                last_inc = idx
        if last_inc >= 0:
            lines.insert(last_inc + 1, '#include <linux/sched/task.h>')
            src = '\n'.join(lines)
            changed = True
    if 'TWA_RESUME' in src and '#ifndef TWA_NONE' not in src:
        src = ('#ifndef TWA_NONE\n#define TWA_NONE 0\n#endif\n'
               '#ifndef TWA_RESUME\n#define TWA_RESUME TWA_NONE\n#endif\n') + src
        changed = True
    if changed:
        open(al, 'w').write(src)
        print('allowlist 5.4 compat patched')

# supercall.c also uses TWA_RESUME (5.7+)
sc = 'drivers/kernelsu/supercall/supercall.c'
if os.path.exists(sc):
    src = open(sc).read()
    if 'TWA_RESUME' in src and '#ifndef TWA_NONE' not in src:
        src = ('#ifndef TWA_NONE\n#define TWA_NONE 0\n#endif\n'
               '#ifndef TWA_RESUME\n#define TWA_RESUME TWA_NONE\n#endif\n') + src
        open(sc, 'w').write(src)
        print('supercall 5.4 compat patched')

# app_profile.c uses seccomp.filter_count (5.7+)
ap = 'drivers/kernelsu/policy/app_profile.c'
if os.path.exists(ap):
    src = open(ap).read()
    if 'filter_count' in src and 'KERNEL_VERSION(5, 7, 0)' not in src:
        src = src.replace('atomic_set(&current->seccomp.filter_count, 0);',
                          '#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)\n    atomic_set(&current->seccomp.filter_count, 0);\n#endif')
        open(ap, 'w').write(src)
        print('app_profile 5.4 compat patched')

# selinux rules.c + sepolicy.c use 5.10+ selinux_policy struct: stub for 5.4
RULES_STUB = '"""#include <linux/version.h>\n#include <linux/uaccess.h>\n#include <linux/types.h>\n#include "selinux.h"\n\nvoid apply_kernelsu_rules()\n{\n}\n\nint handle_sepolicy(void __user *user_data, u64 data_len)\n{\n    return 0;\n}\n"""'
SEP_STUB = '"""#include <linux/version.h>\n#include <linux/types.h>\n#include "sepolicy.h"\n\nstruct selinux_policy;\nstruct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol) { return NULL; }\nvoid ksu_destroy_sepolicy(struct selinux_policy *orig) {}\nbool ksu_type(struct policydb *db, const char *name, const char *attr) { return false; }\nbool ksu_attribute(struct policydb *db, const char *name) { return false; }\nbool ksu_permissive(struct policydb *db, const char *type) { return false; }\nbool ksu_enforce(struct policydb *db, const char *type) { return false; }\nbool ksu_typeattribute(struct policydb *db, const char *type, const char *attr) { return false; }\nbool ksu_exists(struct policydb *db, const char *type) { return false; }\nbool ksu_allow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm) { return false; }\nbool ksu_deny(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm) { return false; }\nbool ksu_auditallow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm) { return false; }\nbool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm) { return false; }\nbool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range) { return false; }\nbool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range) { return false; }\nbool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range) { return false; }\nbool ksu_type_transition(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def, const char *obj) { return false; }\nbool ksu_type_change(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def) { return false; }\nbool ksu_type_member(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def) { return false; }\nbool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *ctx) { return false; }\n"""'
sr = 'drivers/kernelsu/selinux/rules.c'
if os.path.exists(sr):
    open(sr, 'w').write(RULES_STUB)
    print('selinux rules stubbed for 5.4')
sp = 'drivers/kernelsu/selinux/sepolicy.c'
if os.path.exists(sp):
    open(sp, 'w').write(SEP_STUB)
    print('selinux sepolicy stubbed for 5.4')