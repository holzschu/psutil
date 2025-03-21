/*
 * Copyright (c) 2009, Jay Loden, Giampaolo Rodola'. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Disk related functions. Original code was refactored and moved
// from psutil/_psutil_osx.c in 2023. This is the GIT blame before the move:
// https://github.com/giampaolo/psutil/blame/efd7ed3/psutil/_psutil_osx.c

#include <Python.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
// #include <IOKit/storage/IOBlockStorageDriver.h>
// #include <IOKit/storage/IOMedia.h>
// #include <IOKit/IOBSD.h>

#include "../../_psutil_common.h"


/*
 * Return a list of tuples including device, mount point and fs type
 * for all partitions mounted on the system.
 */
PyObject *
psutil_disk_partitions(PyObject *self, PyObject *args) {
    int num;
    int i;
    int len;
    uint64_t flags;
    char opts[400];
    struct statfs *fs = NULL;
    PyObject *py_dev = NULL;
    PyObject *py_mountp = NULL;
    PyObject *py_tuple = NULL;
    PyObject *py_retlist = PyList_New(0);

    if (py_retlist == NULL)
        return NULL;

    // get the number of mount points
    Py_BEGIN_ALLOW_THREADS
    num = getfsstat(NULL, 0, MNT_NOWAIT);
    Py_END_ALLOW_THREADS
    if (num == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    len = sizeof(*fs) * num;
    fs = malloc(len);
    if (fs == NULL) {
        PyErr_NoMemory();
        goto error;
    }

    Py_BEGIN_ALLOW_THREADS
    num = getfsstat(fs, len, MNT_NOWAIT);
    Py_END_ALLOW_THREADS
    if (num == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    for (i = 0; i < num; i++) {
        opts[0] = 0;
        flags = fs[i].f_flags;

        // see sys/mount.h
        if (flags & MNT_RDONLY)
            strlcat(opts, "ro", sizeof(opts));
        else
            strlcat(opts, "rw", sizeof(opts));
        if (flags & MNT_SYNCHRONOUS)
            strlcat(opts, ",sync", sizeof(opts));
        if (flags & MNT_NOEXEC)
            strlcat(opts, ",noexec", sizeof(opts));
        if (flags & MNT_NOSUID)
            strlcat(opts, ",nosuid", sizeof(opts));
        if (flags & MNT_UNION)
            strlcat(opts, ",union", sizeof(opts));
        if (flags & MNT_ASYNC)
            strlcat(opts, ",async", sizeof(opts));
        if (flags & MNT_EXPORTED)
            strlcat(opts, ",exported", sizeof(opts));
        if (flags & MNT_LOCAL)
            strlcat(opts, ",local", sizeof(opts));
        if (flags & MNT_QUOTA)
            strlcat(opts, ",quota", sizeof(opts));
        if (flags & MNT_ROOTFS)
            strlcat(opts, ",rootfs", sizeof(opts));
        if (flags & MNT_DOVOLFS)
            strlcat(opts, ",dovolfs", sizeof(opts));
        if (flags & MNT_DONTBROWSE)
            strlcat(opts, ",dontbrowse", sizeof(opts));
        if (flags & MNT_IGNORE_OWNERSHIP)
            strlcat(opts, ",ignore-ownership", sizeof(opts));
        if (flags & MNT_AUTOMOUNTED)
            strlcat(opts, ",automounted", sizeof(opts));
        if (flags & MNT_JOURNALED)
            strlcat(opts, ",journaled", sizeof(opts));
        if (flags & MNT_NOUSERXATTR)
            strlcat(opts, ",nouserxattr", sizeof(opts));
        if (flags & MNT_DEFWRITE)
            strlcat(opts, ",defwrite", sizeof(opts));
        if (flags & MNT_UPDATE)
            strlcat(opts, ",update", sizeof(opts));
        if (flags & MNT_RELOAD)
            strlcat(opts, ",reload", sizeof(opts));
        if (flags & MNT_FORCE)
            strlcat(opts, ",force", sizeof(opts));
        if (flags & MNT_CMDFLAGS)
            strlcat(opts, ",cmdflags", sizeof(opts));
        // requires macOS >= 10.5
#ifdef MNT_QUARANTINE
        if (flags & MNT_QUARANTINE)
            strlcat(opts, ",quarantine", sizeof(opts));
#endif
#ifdef MNT_MULTILABEL
        if (flags & MNT_MULTILABEL)
            strlcat(opts, ",multilabel", sizeof(opts));
#endif
#ifdef MNT_NOATIME
        if (flags & MNT_NOATIME)
            strlcat(opts, ",noatime", sizeof(opts));
#endif
        py_dev = PyUnicode_DecodeFSDefault(fs[i].f_mntfromname);
        if (! py_dev)
            goto error;
        py_mountp = PyUnicode_DecodeFSDefault(fs[i].f_mntonname);
        if (! py_mountp)
            goto error;
        py_tuple = Py_BuildValue(
            "(OOss)",
            py_dev,               // device
            py_mountp,            // mount point
            fs[i].f_fstypename,   // fs type
            opts);                // options
        if (!py_tuple)
            goto error;
        if (PyList_Append(py_retlist, py_tuple))
            goto error;
        Py_CLEAR(py_dev);
        Py_CLEAR(py_mountp);
        Py_CLEAR(py_tuple);
    }

    free(fs);
    return py_retlist;

error:
    Py_XDECREF(py_dev);
    Py_XDECREF(py_mountp);
    Py_XDECREF(py_tuple);
    Py_DECREF(py_retlist);
    if (fs != NULL)
        free(fs);
    return NULL;
}


PyObject *
psutil_disk_usage_used(PyObject *self, PyObject *args) {
    PyObject *py_default_value;
    PyObject *py_mount_point_bytes = NULL;
    char* mount_point;

    if (!PyArg_ParseTuple(args, "O&O", PyUnicode_FSConverter, &py_mount_point_bytes, &py_default_value)) {
        return NULL;
    }
    mount_point = PyBytes_AsString(py_mount_point_bytes);
    if (NULL == mount_point) {
        Py_XDECREF(py_mount_point_bytes);
        return NULL;
    }

#ifdef ATTR_VOL_SPACEUSED
    /* Call getattrlist(ATTR_VOL_SPACEUSED) to get used space info. */
    int ret;
    struct {
        uint32_t size;
        uint64_t spaceused;
    } __attribute__((aligned(4), packed)) attrbuf = {0};
    struct attrlist attrs = {0};

    attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
    attrs.volattr = ATTR_VOL_INFO | ATTR_VOL_SPACEUSED;
    Py_BEGIN_ALLOW_THREADS
    ret = getattrlist(mount_point, &attrs, &attrbuf, sizeof(attrbuf), 0);
    Py_END_ALLOW_THREADS
    if (ret == 0) {
        Py_XDECREF(py_mount_point_bytes);
        return PyLong_FromUnsignedLongLong(attrbuf.spaceused);
    }
    psutil_debug("getattrlist(ATTR_VOL_SPACEUSED) failed, fall-back to default value");
#endif
    Py_XDECREF(py_mount_point_bytes);
    Py_INCREF(py_default_value);
    return py_default_value;
}


/*
 * Return a Python dict of tuples for disk I/O information
 */
PyObject *
psutil_disk_io_counters(PyObject *self, PyObject *args) {
	PyErr_SetString(
			PyExc_RuntimeError, "unable to get the list of disks.");
    return NULL;
}
