/*
 * Copyright (c) 2009, Jay Loden, Giampaolo Rodola'. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Sensors related functions. Original code was refactored and moved
// from psutil/_psutil_osx.c in 2023. This is the GIT blame before the move:
// https://github.com/giampaolo/psutil/blame/efd7ed3/psutil/_psutil_osx.c
// Original battery code:
// https://github.com/giampaolo/psutil/commit/e0df5da


#include <Python.h>
#include <CoreFoundation/CoreFoundation.h>
// #include <IOKit/ps/IOPowerSources.h>
// #include <IOKit/ps/IOPSKeys.h>
#include <UIKit/UIKit.h>

#include "../../_psutil_common.h"


PyObject *
psutil_sensors_battery(PyObject *self, PyObject *args) {
    PyObject *py_tuple = NULL;
    uint32_t capacity;     /* units are percent */
    int time_to_empty;     /* units are minutes */
    int is_power_plugged;

	switch (UIDevice.currentDevice.batteryState) {
		case UIDeviceBatteryStateFull:
		case UIDeviceBatteryStateCharging:
			is_power_plugged = 1;
			break;
		case UIDeviceBatteryStateUnknown:
	    case UIDeviceBatteryStateUnplugged:
		default:
			is_power_plugged = 0;

	}
	capacity = 100 * UIDevice.currentDevice.batteryLevel;

	/* This value is recommended for non-Apple power sources, so it's not
	 * an error if it doesn't exist. We'll return -1 for "unknown" */
	/* A value of -1 indicates "Still Calculating the Time" also for
	 * apple power source */
	time_to_empty = -1; 

    py_tuple = Py_BuildValue("Iii",
        capacity, time_to_empty, is_power_plugged);
    if (!py_tuple) {
    	return NULL;
    }

    return py_tuple;
}
