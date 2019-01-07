#!/usr/bin/env python3

# Copyright
#   Yclept Nemo <pscjtwjdjtAhnbjm/dpn> 2015
# License
#   GPLv3+
# Notes:
#   Based on Clinton Hall's collection (GPLv2):
#   https://github.com/clinton-hall/GetScripts/


##############################################################################
### NZBGET POST-PROCESSING SCRIPT                                          ###

# Restore default SELinux security contexts
#
# This scripts applies "restorecon" to each successfully downloaded file
# and directory. The entire context (user,role,range,type) is modified, ie.
# assume -F. For more information see "restorecon(8)". 
#
# Requires: python3 >= 3.4
# Requires: libselinux-python

### NZBGET POST-PROCESSING SCRIPT                                          ###
##############################################################################


import enum
import os
import sys
import stat
import os.path
import selinux
import itertools
import traceback


##############################################################################
### improved libselinux-python bindings
##############################################################################

class LabelNotFoundError(OSError):
    pass


def matchpathcon(path, mode):
    try:
        status, context = selinux.matchpathcon(path, mode)
    except FileNotFoundError as e:
        if os.path.exists(path):
            raise LabelNotFoundError(e.errno, "No such label", path) from e
        else:
            e.filename = path
            raise
    return context

def lsetfilecon(path, context):
    selinux.lsetfilecon(path, context)

def restorecon_single(path):
    try:
        mode = os.lstat(path)[stat.ST_MODE]
    except FileNotFoundError:
        path = os.path.realpath(os.path.expanduser(path))
        mode = os.lstat(path)[stat.ST_MODE]

    context_default = matchpathcon(path, mode)

    context_old = selinux.lgetfilecon(path)

    if context_old != context_default:
        lsetfilecon(path, context_default)


##############################################################################
### utilities
##############################################################################

class NZBGetPostProcessExitCode(enum.Enum):
    parcheck    = 92
    success     = 93
    failure     = 94
    none        = 95


class NZBGetLogLevel(enum.Enum):
    detail      = 1
    info        = 2
    warning     = 3
    error       = 4


def nzbget_log(level, message, prefix=""):
    for line in message.rstrip().splitlines():
        print("[{}] {}{}".format(level.name.upper(), prefix, line))

def nzbget_exit(code):
    sys.exit(code.value)

def nzbget_variable(key, version=None):
    try:
        return os.environ[key]
    except KeyError:
        msg = \
            ( "Variable \"{}\" required"
            + ", please upgrade NZBGet to version {} or later" if version else ""
            + "."
            )
        nzbget_log(NZBGetLogLevel.error, msg.format(key, version))
        nzbget_exit(NZBGetPostProcessExitCode.failure)

def descendants(path, onerror=None):
    yield(path)
    for (dirpath, dirnames, filenames) in os.walk(path, onerror=onerror):
        for name in itertools.chain(dirnames, filenames):
            path = os.path.join(dirpath, name)
            yield(path)

def descendants_handler(error):
    msg = "Error while iterating over filesystem: {}"
    nzbget_log(NZBGetLogLevel.warning, msg.format(error))


##############################################################################
### script
##############################################################################

status = nzbget_variable("NZBPP_TOTALSTATUS", "13.0")

if status != "SUCCESS":
    msg = "Download failed with status {}, skipping."
    nzbget_log(NZBGetLogLevel.info, msg.format(status))
    nzbget_exit(NZBGetPostProcessExitCode.none)

directory = nzbget_variable("NZBPP_DIRECTORY")

# Reprocessing deleted history items shouldn't result in failure
if not os.path.exists(directory):
    msg = "Nothing to post-process, destination \"{}\" doesn't exist."
    nzbget_log(NZBGetLogLevel.info, msg.format(directory))
    nzbget_exit(NZBGetPostProcessExitCode.none)

for path in descendants(directory, descendants_handler):
    try:
        restorecon_single(path)
    except FileNotFoundError as e:
        msg = "Expected path \"{}\" does not exist, aborting."
        nzbget_log(NZBGetLogLevel.error, msg.format(path))
        nzbget_exit(NZBGetPostProcessExitCode.failure)
    except LabelNotFoundError as e:
        msg = "No default SELinux context for \"{}\", skipping."
        nzbget_log(NZBGetLogLevel.warning, msg.format(path))
    except PermissionError as e:
        msg = "Permission denied for \"{}\", skipping."
        nzbget_log(NZBGetLogLevel.warning, msg.format(path))
    except Exception:
        msg = "Unhandled exception, aborting:"
        tb = traceback.format_exception()
        nzbget_log(NZBGetLogLevel.error, msg)
        nzbget_log(NZBGetLogLevel.error, tb, prefix="  ")
        nzbget_exit(NZBGetPostProcessExitCode.failure)

nzbget_exit(NZBGetPostProcessExitCode.success)
