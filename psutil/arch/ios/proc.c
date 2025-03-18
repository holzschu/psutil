/*
 * Copyright (c) 2009, Jay Loden, Giampaolo Rodola'. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Process related functions. Original code was moved in here from
// psutil/_psutil_osx.c and psutil/arc/osx/process_info.c in 2023.
// For reference, here's the GIT blame history before the move:
// https://github.com/giampaolo/psutil/blame/59504a5/psutil/_psutil_osx.c
// https://github.com/giampaolo/psutil/blame/efd7ed3/psutil/arch/osx/process_info.c

// Code was copied from _psutil_osx.c and edited for iOS specificities in 2025.
// We cannot get the information through the usual channels, so we work around.

#include <Python.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sysctl.h>
// #include <libproc.h>
// #include <sys/proc_info.h>
#include <sys/sysctl.h>
// #include <netinet/tcp_fsm.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <unistd.h>
#include <mach/mach.h>
// #include <mach/mach_vm.h>
// #include <mach/shared_region.h>
#include <mach-o/loader.h>
// iOS additions:
// Include file for fcntl:
#include <fcntl.h>
#include <dlfcn.h> // for dlsym()
// Include file for getrlimit/setrlimit (for proc_num_fds):
#include <sys/resource.h>
static struct rlimit limitFilesOpen;
// Influde file for getsockopt/getsockname:
#include <sys/socket.h>
#include <sys/un.h> // Unix sockets
// TCPS constants, defined manually
#define TCPS_CLOSED             0       /* closed */
#define TCPS_LISTEN             1       /* listening for connection */
#define TCPS_SYN_SENT           2       /* active, have sent syn */
#define TCPS_SYN_RECEIVED       3       /* have send and received syn */
/* states < TCPS_ESTABLISHED are those where connections not established */
#define TCPS_ESTABLISHED        4       /* established */
#define TCPS_CLOSE_WAIT         5       /* rcvd fin, waiting for close */
/* states > TCPS_CLOSE_WAIT are those where user has closed */
#define TCPS_FIN_WAIT_1         6       /* have closed, sent fin */
#define TCPS_CLOSING            7       /* closed xchd FIN; await FIN ACK */
#define TCPS_LAST_ACK           8       /* had fin and close; await FIN ACK */
/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
#define TCPS_FIN_WAIT_2         9       /* have closed, fin is acked */
#define TCPS_TIME_WAIT          10      /* in 2*msl quiet wait after close */


#include "../../_psutil_common.h"
#include "../../_psutil_posix.h"


#define PSUTIL_TV2DOUBLE(t) ((t).tv_sec + (t).tv_usec / 1000000.0)
typedef struct kinfo_proc kinfo_proc;


// ====================================================================
// --- utils
// ====================================================================

/*
 * Returns a list of all BSD processes on the system.  This routine
 * allocates the list and puts it in *procList and a count of the
 * number of entries in *procCount.  You are responsible for freeing
 * this list (use "free" from System framework).
 * On success, the function returns 0.
 * On error, the function returns a BSD errno value.
 */
static int
psutil_get_proc_list(kinfo_proc **procList, size_t *procCount) {
    int mib[3];
    size_t size, size2;
    void *ptr;
    int err;
    int lim = 8;  // some limit

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL;
    *procCount = 0;

    /*
     * We start by calling sysctl with ptr == NULL and size == 0.
     * That will succeed, and set size to the appropriate length.
     * We then allocate a buffer of at least that size and call
     * sysctl with that buffer.  If that succeeds, we're done.
     * If that call fails with ENOMEM, we throw the buffer away
     * and try again.
     * Note that the loop calls sysctl with NULL again.  This is
     * is necessary because the ENOMEM failure case sets size to
     * the amount of data returned, not the amount of data that
     * could have been returned.
     */
    while (lim-- > 0) {
        size = 0;
        if (sysctl((int *)mib, 3, NULL, &size, NULL, 0) == -1) {
            psutil_PyErr_SetFromOSErrnoWithSyscall("sysctl(KERN_PROC_ALL)");
            return 1;
        }
        size2 = size + (size >> 3);  // add some
        if (size2 > size) {
            ptr = malloc(size2);
            if (ptr == NULL)
                ptr = malloc(size);
            else
                size = size2;
        }
        else {
            ptr = malloc(size);
        }
        if (ptr == NULL) {
            PyErr_NoMemory();
            return 1;
        }

        if (sysctl((int *)mib, 3, ptr, &size, NULL, 0) == -1) {
            err = errno;
            free(ptr);
            if (err != ENOMEM) {
                psutil_PyErr_SetFromOSErrnoWithSyscall("sysctl(KERN_PROC_ALL)");
                return 1;
            }
        }
        else {
            *procList = (kinfo_proc *)ptr;
            *procCount = size / sizeof(kinfo_proc);
            if (procCount <= 0) {
                PyErr_Format(PyExc_RuntimeError, "no PIDs found");
                return 1;
            }
            return 0;  // success
        }
    }

    PyErr_Format(PyExc_RuntimeError, "couldn't collect PIDs list");
    return 1;
}


// Read the maximum argument size for processes
static int
psutil_sysctl_argmax() {
    int argmax;
    int mib[2];
    size_t size = sizeof(argmax);

    mib[0] = CTL_KERN;
    mib[1] = KERN_ARGMAX;

    if (sysctl(mib, 2, &argmax, &size, NULL, 0) == 0)
        return argmax;
    psutil_PyErr_SetFromOSErrnoWithSyscall("sysctl(KERN_ARGMAX)");
    return 0;
}


// Read process argument space.
static int
psutil_sysctl_procargs(pid_t pid, char *procargs, size_t *argmax) {
    int mib[3];

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROCARGS2;
    mib[2] = pid;

    if (sysctl(mib, 3, procargs, argmax, NULL, 0) < 0) {
        if (psutil_pid_exists(pid) == 0) {
            NoSuchProcess("psutil_pid_exists -> 0");
            return 1;
        }
        // In case of zombie process we'll get EINVAL. We translate it
        // to NSP and _psosx.py will translate it to ZP.
        if (errno == EINVAL) {
            psutil_debug("sysctl(KERN_PROCARGS2) -> EINVAL translated to NSP");
            NoSuchProcess("sysctl(KERN_PROCARGS2) -> EINVAL");
            return 1;
        }
        // There's nothing we can do other than raising AD.
        if (errno == EIO) {
            psutil_debug("sysctl(KERN_PROCARGS2) -> EIO translated to AD");
            AccessDenied("sysctl(KERN_PROCARGS2) -> EIO");
            return 1;
        }
        psutil_PyErr_SetFromOSErrnoWithSyscall("sysctl(KERN_PROCARGS2)");
        return 1;
    }
    return 0;
}


static int
psutil_get_kinfo_proc(pid_t pid, struct kinfo_proc *kp) {
    int mib[4];
    size_t len;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = pid;

    // fetch the info with sysctl()
    len = sizeof(struct kinfo_proc);

    // now read the data from sysctl
    if (sysctl(mib, 4, kp, &len, NULL, 0) == -1) {
        // raise an exception and throw errno as the error
        psutil_PyErr_SetFromOSErrnoWithSyscall("sysctl");
        return -1;
    }

    // sysctl succeeds but len is zero, happens when process has gone away
    if (len == 0) {
        NoSuchProcess("sysctl(kinfo_proc), len == 0");
        return -1;
    }
    return 0;
}


// ====================================================================
// --- Python APIs
// ====================================================================


/*
 * Return a Python list of all the PIDs running on the system.
 */
PyObject *
psutil_pids(PyObject *self, PyObject *args) {
    kinfo_proc *proclist = NULL;
    kinfo_proc *orig_address = NULL;
    size_t num_processes;
    size_t idx;
    PyObject *py_pid = NULL;
    PyObject *py_retlist = PyList_New(0);

    if (py_retlist == NULL)
        return NULL;

    if (psutil_get_proc_list(&proclist, &num_processes) != 0)
        goto error;

    // save the address of proclist so we can free it later
    orig_address = proclist;
    for (idx = 0; idx < num_processes; idx++) {
        py_pid = PyLong_FromPid(proclist->kp_proc.p_pid);
        if (! py_pid)
            goto error;
        if (PyList_Append(py_retlist, py_pid))
            goto error;
        Py_CLEAR(py_pid);
        proclist++;
    }
    free(orig_address);

    return py_retlist;

error:
    Py_XDECREF(py_pid);
    Py_DECREF(py_retlist);
    if (orig_address != NULL)
        free(orig_address);
    return NULL;
}


/*
 * Return multiple process info as a Python tuple in one shot by
 * using sysctl() and filling up a kinfo_proc struct.
 * It should be possible to do this for all processes without
 * incurring into permission (EPERM) errors.
 * This will also succeed for zombie processes returning correct
 * information.
 */
PyObject *
psutil_proc_kinfo_oneshot(PyObject *self, PyObject *args) {
    pid_t pid;
    struct kinfo_proc kp;
    PyObject *py_name;
    PyObject *py_retlist;

    if (! PyArg_ParseTuple(args, _Py_PARSE_PID, &pid))
        return NULL;
    if (psutil_get_kinfo_proc(pid, &kp) == -1)
        return NULL;

    py_name = PyUnicode_DecodeFSDefault(kp.kp_proc.p_comm);
    if (! py_name) {
        // Likely a decoding error. We don't want to fail the whole
        // operation. The python module may retry with proc_name().
        PyErr_Clear();
        py_name = Py_None;
    }

    py_retlist = Py_BuildValue(
        _Py_PARSE_PID "llllllidiO",
        kp.kp_eproc.e_ppid,                        // (pid_t) ppid
        (long)kp.kp_eproc.e_pcred.p_ruid,          // (long) real uid
        (long)kp.kp_eproc.e_ucred.cr_uid,          // (long) effective uid
        (long)kp.kp_eproc.e_pcred.p_svuid,         // (long) saved uid
        (long)kp.kp_eproc.e_pcred.p_rgid,          // (long) real gid
        (long)kp.kp_eproc.e_ucred.cr_groups[0],    // (long) effective gid
        (long)kp.kp_eproc.e_pcred.p_svgid,         // (long) saved gid
        kp.kp_eproc.e_tdev,                        // (int) tty nr
        PSUTIL_TV2DOUBLE(kp.kp_proc.p_starttime),  // (double) create time
        (int)kp.kp_proc.p_stat,                    // (int) status
        py_name                                    // (pystr) name
    );

    if (py_retlist != NULL) {
        // XXX shall we decref() also in case of Py_BuildValue() error?
        Py_DECREF(py_name);
    }
    return py_retlist;
}


/*
 * Return multiple process info as a Python tuple in one shot by
 * using proc_pidinfo(PROC_PIDTASKINFO) and filling a proc_taskinfo
 * struct.
 * Contrarily from proc_kinfo above this function will fail with
 * EACCES for PIDs owned by another user and with ESRCH for zombie
 * processes.
 */
PyObject *
psutil_proc_pidtaskinfo_oneshot(PyObject *self, PyObject *args) {
    pid_t pid;
    uint64_t total_user;
    uint64_t total_system;
    unsigned int info_count = TASK_BASIC_INFO_COUNT;
    struct task_basic_info tasks_info;
    int err;

    if (! PyArg_ParseTuple(args, _Py_PARSE_PID, &pid))
        return NULL;
    // on iOS, we don't have acces to proc_pidinfo. This attempts to replace it with task_info.
    // if (psutil_proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, sizeof(pti)) <= 0) return NULL;
    info_count = TASK_BASIC_INFO_COUNT;

    err = task_info(mach_task_self_, MACH_TASK_BASIC_INFO, (task_info_t)&tasks_info,
                    &info_count);
    if (err != KERN_SUCCESS) {
        // errcode 4 is "invalid argument" (access denied)
        if (err == 4) {
            AccessDenied("task_info(TASK_BASIC_INFO)");
        }
        else {
            // otherwise throw a runtime error with appropriate error code
            PyErr_Format(PyExc_RuntimeError,
                         "task_info(TASK_BASIC_INFO) syscall failed");
        }
        return NULL;
    }

    
    total_user = tasks_info.user_time.seconds * 1000000 + tasks_info.user_time.microseconds;
    total_system = tasks_info.system_time.seconds * 1000000 + tasks_info.system_time.microseconds;

    return Py_BuildValue(
        "(ddKKkkkk)",
        (float)total_user / 1000000.0,     // (float) cpu user time
        (float)total_system / 1000000.0,   // (float) cpu sys time
        // Note about memory: determining other mem stats on macOS is a mess:
        // http://www.opensource.apple.com/source/top/top-67/libtop.c?txt
        // I just give up.
        // struct proc_regioninfo pri;
        // psutil_proc_pidinfo(pid, PROC_PIDREGIONINFO, 0, &pri, sizeof(pri))
        tasks_info.resident_size,  // (uns long long) rss
        tasks_info.virtual_size,   // (uns long long) vms
        0,         // (uns long) number of page faults (pages)
        1,        // (uns long) number of actual pageins (pages)
        1,      // (uns long) num threads
        // Unvoluntary value seems not to be available;
        // pti.pti_csw probably refers to the sum of the two;
        // getrusage() numbers seems to confirm this theory.
        0             // (uns long) voluntary ctx switches
    );
}


/*
 * Return process name from kinfo_proc as a Python string.
 */
PyObject *
psutil_proc_name(PyObject *self, PyObject *args) {
    pid_t pid;
    struct kinfo_proc kp;

    if (! PyArg_ParseTuple(args, _Py_PARSE_PID, &pid))
        return NULL;
    if (psutil_get_kinfo_proc(pid, &kp) == -1)
        return NULL;
    return PyUnicode_DecodeFSDefault(kp.kp_proc.p_comm);
}


/*
 * Return process current working directory.
 * Raises NSP in case of zombie process.
 */
PyObject *
psutil_proc_cwd(PyObject *self, PyObject *args) {
    char* cwd = getenv("CWD");

    return PyUnicode_DecodeFSDefault(cwd);
}


/*
 * Return path of the process executable.
 */
PyObject *
psutil_proc_exe(PyObject *self, PyObject *args) {
    const char *buf;
    char* (*function)(void) = NULL;
	// If the function ios_progname() is available, we use it:
	// ios_progname is defined in iOS_system. It will be available 
	// if the app has been linked with iOS_system.
    function = dlsym(RTLD_MAIN_ONLY, "ios_progname");
    if (function != NULL) 
    	buf = function();
    // getprogname is always defined 
    // (it will usually be the name of the app on iOS)
	else buf = getprogname();
    return PyUnicode_DecodeFSDefault(buf);
}


/*
 * Returns the USS (unique set size) of the process. Reference:
 * https://dxr.mozilla.org/mozilla-central/source/xpcom/base/
 *     nsMemoryReporterManager.cpp
 */
PyObject *
psutil_proc_memory_uss(PyObject *self, PyObject *args) {
	// That information is just not available on iOS (and probably doesn't apply)
	// We bail out with a value of 0. 
    return Py_BuildValue("K", 0);
}


/*
 * Return process threads
 */
PyObject *
psutil_proc_threads(PyObject *self, PyObject *args) {
    pid_t pid;
    int err, ret;
    kern_return_t kr;
    unsigned int info_count = TASK_BASIC_INFO_COUNT;
    mach_port_t task = MACH_PORT_NULL;
    struct task_basic_info tasks_info;
    thread_act_port_array_t thread_list = NULL;
    thread_info_data_t thinfo_basic;
    thread_basic_info_t basic_info_th;
    mach_msg_type_number_t thread_count, thread_info_count, j;

    PyObject *py_tuple = NULL;
    PyObject *py_retlist = PyList_New(0);

    if (py_retlist == NULL)
        return NULL;

    if (! PyArg_ParseTuple(args, _Py_PARSE_PID, &pid))
        goto error;

    info_count = TASK_BASIC_INFO_COUNT;
    err = task_info(mach_task_self_, TASK_BASIC_INFO, (task_info_t)&tasks_info,
                    &info_count);
    if (err != KERN_SUCCESS) {
        // errcode 4 is "invalid argument" (access denied)
        if (err == 4) {
            AccessDenied("task_info(TASK_BASIC_INFO)");
        }
        else {
            // otherwise throw a runtime error with appropriate error code
            PyErr_Format(PyExc_RuntimeError,
                         "task_info(TASK_BASIC_INFO) syscall failed");
        }
        goto error;
    }

    err = task_threads(task, &thread_list, &thread_count);
    if (err != KERN_SUCCESS) {
        PyErr_Format(PyExc_RuntimeError, "task_threads() syscall failed");
        goto error;
    }

    for (j = 0; j < thread_count; j++) {
        thread_info_count = THREAD_INFO_MAX;
        kr = thread_info(thread_list[j], THREAD_BASIC_INFO,
                         (thread_info_t)thinfo_basic, &thread_info_count);
        if (kr != KERN_SUCCESS) {
            PyErr_Format(PyExc_RuntimeError,
                         "thread_info(THREAD_BASIC_INFO) syscall failed");
            goto error;
        }

        basic_info_th = (thread_basic_info_t)thinfo_basic;
        py_tuple = Py_BuildValue(
            "Iff",
            j + 1,
            basic_info_th->user_time.seconds + \
                (float)basic_info_th->user_time.microseconds / 1000000.0,
            basic_info_th->system_time.seconds + \
                (float)basic_info_th->system_time.microseconds / 1000000.0
        );
        if (!py_tuple)
            goto error;
        if (PyList_Append(py_retlist, py_tuple))
            goto error;
        Py_CLEAR(py_tuple);
    }

    ret = vm_deallocate(task, (vm_address_t)thread_list,
                        thread_count * sizeof(int));
    if (ret != KERN_SUCCESS)
        PyErr_WarnEx(PyExc_RuntimeWarning, "vm_deallocate() failed", 2);

    mach_port_deallocate(mach_task_self(), task);

    return py_retlist;

error:
    if (task != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), task);
    Py_XDECREF(py_tuple);
    Py_DECREF(py_retlist);
    if (thread_list != NULL) {
        ret = vm_deallocate(task, (vm_address_t)thread_list,
                            thread_count * sizeof(int));
        if (ret != KERN_SUCCESS)
            PyErr_WarnEx(PyExc_RuntimeWarning, "vm_deallocate() failed", 2);
    }
    return NULL;
}


/*
 * Return process open files as a Python tuple.
 * References:
 * - lsof source code: https://github.com/apple-opensource/lsof/blob/28/lsof/dialects/darwin/libproc/dproc.c#L342
 * - /usr/include/sys/proc_info.h
 */
PyObject *
psutil_proc_open_files(PyObject *self, PyObject *args) {
    pid_t pid;
    PyObject *py_retlist = PyList_New(0);
    PyObject *py_tuple = NULL;
    PyObject *py_path = NULL;

    if (py_retlist == NULL)
        return NULL;

    if (! PyArg_ParseTuple(args, _Py_PARSE_PID, &pid))
        goto error;

    // see: https://github.com/giampaolo/psutil/issues/2116
    if (pid == 0)
        return py_retlist;

	// iOS version: we loop over all possible file descriptors, and check fstat.
	// (the file descriptors opened are actually attached to the current process, 
	// which is also the current app. The max number is around 2048, so this O(n)
	// approach is not too expensive).
    getrlimit(RLIMIT_NOFILE, &limitFilesOpen);
	for (unsigned long long fd = 0; fd < limitFilesOpen.rlim_cur; fd++) {
		errno = 0;
		int flags = fcntl(fd, F_GETFD, 0);
		if (flags == -1 && errno) {
			continue;
		}
		// At this point, fd is a valid, open file descriptor. 
		struct stat statbuf;
		int r = fstat(fd, &statbuf);
		if (r < 0) 
			continue; // let's assume the file has been closed in the meantime
		if (S_ISREG(statbuf.st_mode)) {
			// it's a regular file
			char path[MAXPATHLEN];
			r = fcntl(fd, F_GETPATH, path);
			if (r < 0) 
				continue; // We didn't get the path, let's assume the file is closed.
            // --- construct python list
            py_path = PyUnicode_DecodeFSDefault(path);
            if (! py_path)
                goto error;
            py_tuple = Py_BuildValue(
                "(Oi)",
                py_path,
                (int)fd);
            if (!py_tuple)
                goto error;
            if (PyList_Append(py_retlist, py_tuple))
                goto error;
            Py_CLEAR(py_tuple);
            Py_CLEAR(py_path);
            // --- /construct python list
		}
	}

    return py_retlist;

error:
    Py_XDECREF(py_tuple);
    Py_XDECREF(py_path);
    Py_DECREF(py_retlist);
    return NULL;  // exception has already been set earlier
}


/*
 * Return process TCP and UDP connections as a list of tuples.
 * Raises NSP in case of zombie process.
 * References:
 * - lsof source code: https://github.com/apple-opensource/lsof/blob/28/lsof/dialects/darwin/libproc/dproc.c#L342
 * - /usr/include/sys/proc_info.h
 */
PyObject *
psutil_proc_net_connections(PyObject *self, PyObject *args) {
    pid_t pid;
    PyObject *py_retlist = PyList_New(0);
    PyObject *py_tuple = NULL;
    PyObject *py_laddr = NULL;
    PyObject *py_raddr = NULL;
    PyObject *py_af_filter = NULL;
    PyObject *py_type_filter = NULL;

    if (py_retlist == NULL)
        return NULL;

    if (! PyArg_ParseTuple(args, _Py_PARSE_PID "OO", &pid, &py_af_filter,
                           &py_type_filter)) {
        goto error;
    }

    // see: https://github.com/giampaolo/psutil/issues/2116
    if (pid == 0)
        return py_retlist;

    if (!PySequence_Check(py_af_filter) || !PySequence_Check(py_type_filter)) {
        PyErr_SetString(PyExc_TypeError, "arg 2 or 3 is not a sequence");
        goto error;
    }


	// iOS version: we loop over all possible file descriptors, and check fstat.
	// (the file descriptors opened are actually attached to the current process, 
	// which is also the current app. The max number is around 2048, so this O(n)
	// approach is not too expensive).
    getrlimit(RLIMIT_NOFILE, &limitFilesOpen);
	for (unsigned long long fd = 0; fd < limitFilesOpen.rlim_cur; fd++) {
		errno = 0;
		int flags = fcntl(fd, F_GETFD, 0);
		if (flags == -1 && errno) {
			continue;
		}
		// At this point, fd is a valid, open file descriptor. 
		struct stat statbuf;
		int r = fstat(fd, &statbuf);
		if (r < 0) 
			continue; // let's assume the file has been closed in the meantime
		if (S_ISSOCK(statbuf.st_mode)) {
			// it's a socket. Good. Now let's get its info.
            int family, type, lport, rport, state;
            // TODO: use INET6_ADDRSTRLEN instead of 200
            char lip[200], rip[200];
            int inseq;
            PyObject *py_family;
            PyObject *py_type;
			struct sockaddr lsa; // local socket address
			struct sockaddr rsa; // remote socket address
			unsigned int addr_len = sizeof(lsa);
			int ret = getsockname(fd, &lsa, &addr_len);
			if (ret < 0) 
				continue; 
			ret = getpeername(fd, &rsa, &addr_len);
			if (ret < 0) 
				continue; 
			family = lsa.sa_family; 
			unsigned int option_len = sizeof(type); 
			ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &option_len);
			if (ret < 0) 
				continue; 
            // apply filters
            py_family = PyLong_FromLong((long)family);
            inseq = PySequence_Contains(py_af_filter, py_family);
            Py_DECREF(py_family);
            if (inseq == 0)
                continue;
            py_type = PyLong_FromLong((long)type);
            inseq = PySequence_Contains(py_type_filter, py_type);
            Py_DECREF(py_type);
            if (inseq == 0)
                continue;
            if ((family == AF_INET) || (family == AF_INET6)) {
                if (family == AF_INET) {
                	struct sockaddr_in *si = (struct sockaddr_in *)(void *) &lsa;
                	// No way to get the local host address (lip). 
                    inet_ntop(AF_INET, &si->sin_addr, lip, sizeof(lip));
					lport = ntohs(si->sin_port);
                    // remote host address:
                    si =  (struct sockaddr_in *)(void *) &rsa;
                    inet_ntop(AF_INET, &si->sin_addr, rip, sizeof(rip));
					rport = ntohs(si->sin_port);
                }
                else {
                	struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)(void *) &lsa;
                    inet_ntop(AF_INET6, &si6->sin6_addr, lip, sizeof(lip));
					lport = ntohs(si6->sin6_port);
                    si6 = (struct sockaddr_in6 *)(void *) &rsa;
                    inet_ntop(AF_INET6, &si6->sin6_addr, rip, sizeof(rip));
					rport = ntohs(si6->sin6_port);
                }

                // check for inet_ntop failures
                if (errno != 0) {
                    psutil_PyErr_SetFromOSErrnoWithSyscall("inet_ntop()");
                    goto error;
                }
				// We use getsockopt to get the socket status:
                // It doesn't provide a lot of information, though.
                if (type == SOCK_STREAM) {
                	int error; 
                	unsigned int slen = sizeof(error);
                	ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &slen);
                	if ((ret == 0) && (error == 0))
						state = TCPS_ESTABLISHED;
					else 
                		state = TCPS_CLOSED;
				} else
                    state = PSUTIL_CONN_NONE;

                py_laddr = Py_BuildValue("(si)", lip, lport);
                if (!py_laddr)
                    goto error;
                if (rport != 0)
                    py_raddr = Py_BuildValue("(si)", rip, rport);
                else
                    py_raddr = Py_BuildValue("()");
                if (!py_raddr)
                    goto error;

                // construct the python list
                py_tuple = Py_BuildValue(
                    "(iiiNNi)", fd, family, type, py_laddr, py_raddr, state);
                if (!py_tuple)
                    goto error;
                if (PyList_Append(py_retlist, py_tuple))
                    goto error;
                Py_CLEAR(py_tuple);
            }
            else if (family == AF_UNIX) {
				struct sockaddr_un *su = (struct sockaddr_un *)(void *) &lsa;
                py_laddr = PyUnicode_DecodeFSDefault(su->sun_path); 
                if (!py_laddr)
                    goto error;
				su = (struct sockaddr_un *)(void *) &rsa;
                py_raddr = PyUnicode_DecodeFSDefault(su->sun_path); 
                if (!py_raddr)
                    goto error;
                // construct the python list
                py_tuple = Py_BuildValue(
                    "(iiiOOi)",
                    fd, family, type,
                    py_laddr,
                    py_raddr,
                    PSUTIL_CONN_NONE);
                if (!py_tuple)
                    goto error;
                if (PyList_Append(py_retlist, py_tuple))
                    goto error;
                Py_CLEAR(py_tuple);
                Py_CLEAR(py_laddr);
                Py_CLEAR(py_raddr);
            }
		}
	}

    return py_retlist;

error:
    Py_XDECREF(py_tuple);
    Py_XDECREF(py_laddr);
    Py_XDECREF(py_raddr);
    Py_DECREF(py_retlist);
    return NULL;
}


/*
 * Return number of file descriptors opened by process.
 * Raises NSP in case of zombie process.
 */
// iOS specific: this will return the total number of file descriptors opened in the app
// That's the best we can do (and close enough since all is a single process).
PyObject *
psutil_proc_num_fds(PyObject *self, PyObject *args) {
	int numFileDescriptorsOpen = 0;
    getrlimit(RLIMIT_NOFILE, &limitFilesOpen);
	for (unsigned long long fd = 0; fd < limitFilesOpen.rlim_cur; fd++) {
		errno = 0;
		int flags = fcntl(fd, F_GETFD, 0);
		if (flags == -1 && errno) {
			continue;
		}
		++numFileDescriptorsOpen ;
	}
    return Py_BuildValue("i", numFileDescriptorsOpen);
}


// return process args as a python list
PyObject *
psutil_proc_cmdline(PyObject *self, PyObject *args) {
    pid_t pid;
    int nargs;
    size_t len;
    char *procargs = NULL;
    char *arg_ptr;
    char *arg_end;
    char *curr_arg;
    size_t argmax;
    PyObject *py_retlist = PyList_New(0);
    PyObject *py_arg = NULL;

    if (py_retlist == NULL)
        return NULL;
    if (! PyArg_ParseTuple(args, _Py_PARSE_PID, &pid))
        goto error;

    // special case for PID 0 (kernel_task) where cmdline cannot be fetched
    if (pid == 0)
        return py_retlist;

    // read argmax and allocate memory for argument space.
    argmax = psutil_sysctl_argmax();
    if (! argmax)
        goto error;

    procargs = (char *)malloc(argmax);
    if (NULL == procargs) {
        PyErr_NoMemory();
        goto error;
    }

    if (psutil_sysctl_procargs(pid, procargs, &argmax) != 0)
        goto error;

    arg_end = &procargs[argmax];
    // copy the number of arguments to nargs
    memcpy(&nargs, procargs, sizeof(nargs));

    arg_ptr = procargs + sizeof(nargs);
    len = strlen(arg_ptr);
    arg_ptr += len + 1;

    if (arg_ptr == arg_end) {
        free(procargs);
        return py_retlist;
    }

    // skip ahead to the first argument
    for (; arg_ptr < arg_end; arg_ptr++) {
        if (*arg_ptr != '\0')
            break;
    }

    // iterate through arguments
    curr_arg = arg_ptr;
    while (arg_ptr < arg_end && nargs > 0) {
        if (*arg_ptr++ == '\0') {
            py_arg = PyUnicode_DecodeFSDefault(curr_arg);
            if (! py_arg)
                goto error;
            if (PyList_Append(py_retlist, py_arg))
                goto error;
            Py_DECREF(py_arg);
            // iterate to next arg and decrement # of args
            curr_arg = arg_ptr;
            nargs--;
        }
    }

    free(procargs);
    return py_retlist;

error:
    Py_XDECREF(py_arg);
    Py_XDECREF(py_retlist);
    if (procargs != NULL)
        free(procargs);
    return NULL;
}


// Return process environment as a python string.
// On Big Sur this function returns an empty string unless:
// * kernel is DEVELOPMENT || DEBUG
// * target process is same as current_proc()
// * target process is not cs_restricted
// * SIP is off
// * caller has an entitlement
// See: https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/kern/kern_sysctl.c#L1315-L1321
PyObject *
psutil_proc_environ(PyObject *self, PyObject *args) {
    pid_t pid;
    int nargs;
    char *procargs = NULL;
    char *procenv = NULL;
    char *arg_ptr;
    char *arg_end;
    char *env_start;
    size_t argmax;
    PyObject *py_ret = NULL;

    if (! PyArg_ParseTuple(args, _Py_PARSE_PID, &pid))
        return NULL;

    // special case for PID 0 (kernel_task) where cmdline cannot be fetched
    if (pid == 0)
        goto empty;

    // read argmax and allocate memory for argument space.
    argmax = psutil_sysctl_argmax();
    if (! argmax)
        goto error;

    procargs = (char *)malloc(argmax);
    if (NULL == procargs) {
        PyErr_NoMemory();
        goto error;
    }

    if (psutil_sysctl_procargs(pid, procargs, &argmax) != 0)
        goto error;

    arg_end = &procargs[argmax];
    // copy the number of arguments to nargs
    memcpy(&nargs, procargs, sizeof(nargs));

    // skip executable path
    arg_ptr = procargs + sizeof(nargs);
    arg_ptr = memchr(arg_ptr, '\0', arg_end - arg_ptr);

    if (arg_ptr == NULL || arg_ptr == arg_end) {
        psutil_debug(
            "(arg_ptr == NULL || arg_ptr == arg_end); set environ to empty");
        goto empty;
    }

    // skip ahead to the first argument
    for (; arg_ptr < arg_end; arg_ptr++) {
        if (*arg_ptr != '\0')
            break;
    }

    // iterate through arguments
    while (arg_ptr < arg_end && nargs > 0) {
        if (*arg_ptr++ == '\0')
            nargs--;
    }

    // build an environment variable block
    env_start = arg_ptr;

    procenv = calloc(1, arg_end - arg_ptr);
    if (procenv == NULL) {
        PyErr_NoMemory();
        goto error;
    }

    while (*arg_ptr != '\0' && arg_ptr < arg_end) {
        char *s = memchr(arg_ptr + 1, '\0', arg_end - arg_ptr);
        if (s == NULL)
            break;
        memcpy(procenv + (arg_ptr - env_start), arg_ptr, s - arg_ptr);
        arg_ptr = s + 1;
    }

    py_ret = PyUnicode_DecodeFSDefaultAndSize(
        procenv, arg_ptr - env_start + 1);
    if (!py_ret) {
        // XXX: don't want to free() this as per:
        // https://github.com/giampaolo/psutil/issues/926
        // It sucks but not sure what else to do.
        procargs = NULL;
        goto error;
    }

    free(procargs);
    free(procenv);
    return py_ret;

empty:
    if (procargs != NULL)
        free(procargs);
    return Py_BuildValue("s", "");

error:
    Py_XDECREF(py_ret);
    if (procargs != NULL)
        free(procargs);
    if (procenv != NULL)
        free(procargs);
    return NULL;
}
