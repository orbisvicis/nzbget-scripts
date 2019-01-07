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

# Restore default permissions.
#
# Overview:
# Processes directories, and links to valid directories if you wish to
# reprocess entries that have been moved and linked to from the destination
# directory by a third-party. Only enable if all download or archive
# content should have permissions restored.
#
# Assumptions:
# The main program (nzbget) doesn't override default permissions and the
# destination directory (NZBPP_DIRECTORY) is always created, not moved
# (explained below).
# 
# This script restores inheritable filesystem permissions (ACLs and setgid)
# on child objects from the destination directory, NZBPP_DIRECTORY. As such
# the destination directory must have valid inheritable permissions. If the
# destination directory was created, it will inherit valid permissions from
# its parent directory. This is what nzbget currently does, even if the
# target consists of a single file. If the destination directory was moved,
# its inherited permissions must be adjusted to that of its new parent. If
# the destination directory is a link, its target permissions should
# reflect that of the target's parent, not the link's parent, otherwise
# this script will set incorrect inheritable permissions.
#
# If the destination directory is modified by a third-party process before
# this script is run, the process-based permissions (standard permissions
# excluding setgid) this script applies might not reflect the desired
# permissions. Before enabling this script, ensure nzbget's umask is
# compatible with that of the other process.
#
# Process:
# If the destination directory contains a default ACL, then for itself and
# each descendant:
#   * set the inheritable permission attributes (setgid) from the
#     destination directory
#   * clear the non-inheritable permission attributes (setuid, sticky)
#   * set the ACL (and default ACL if directory) to the default ACL of the
#     destination directory
# Otherwise this script assumes process-based permissions, and for the
# destination directory and each descendant:
#   * restore permissions, excluding the inheritable permission attribute
#     (setgid), from umask
#   * set the inheritable permission attribute (setgid) from the
#     destination directory
#   * discard any extended ACLs (certain archive formats, such as *star,
#     preserve ACLs)
#
# Requirements:
# Requires: python3 >= 3.4
# Requires: pylibacl

### NZBGET POST-PROCESSING SCRIPT                                          ###
##############################################################################


import enum
import os
import sys
import stat
import os.path
import posix1e
import itertools
import functools
import traceback


##############################################################################
### utilities: system
##############################################################################

def descendants(path, onerror=None):
    yield(path)
    for (dirpath, dirnames, filenames) in os.walk(path, onerror=onerror):
        for name in itertools.chain(dirnames, filenames):
            path = os.path.join(dirpath, name)
            yield(path)

def umask_get():
    umask_current = os.umask(0)
    os.umask(umask_current)
    return (umask_current & 0o0777)

def parent_path(path):
    return os.path.join(path, os.path.pardir)

def acl_has_mask(acl):
    for entry in acl:
        if entry.tag_type == posix1e.ACL_MASK:
            return True
    return False

# Process-based permissions
#
# Duplicates the functionality of the "chmod" command, which differs from the
# System or C equivalents. In other words, by default:
#   * files
#       resets S_ISUID, S_ISGID, S_ISVTX.
#   * directories
#       resets S_ISVTX
#       preserves S_ISUID, S_ISGID
# The "mask" option overrides which directory bits are preserved but is
# restricted to a subset of (S_ISUID | S_ISGID).
#
# Link permissions cannot be changed; the permissions of the referenced file
# can, optionally. The "chmod" utility by default dereferences links unless in
# recursive mode.
def restoremode(path, followlinks=True, mask=None):
    mask_mask = stat.S_ISUID | stat.S_ISGID
    mask = (mask_mask) if mask is None else (mask & mask_mask)
    mode_stat = os.lstat(path)[stat.ST_MODE]
    if stat.S_ISLNK(mode_stat) and not followlinks:
        return
    mode_stat = os.stat(path)[stat.ST_MODE]
    umask = umask_get()
    if stat.S_ISDIR(mode_stat):
        mode_attr = mode_stat & mask
        mode_perm = (0o0777 - umask) | mode_attr
    else:
        mode_perm = (0o0666 - umask)
    os.chmod(path, mode_perm)

# Process-based permissions
#
# Restore permission attributes: the S_ISUID, S_ISGID and S_ISVTX bits. Since
# umask ignores permission attributes - they must be manually set via "chmod" -
# for the most part this function simply clears (zeroes) the bits... Except:
# 
# On most systems, when applied to directories, the S_ISGID bit becomes an
# inheritable file-system based attribute. Therefore this bit is ignored
# (preserved) by default on directories. If necessary the option "mask"
# overrides this behaviour, however:
#   * mask must be a subset of (S_ISUID | S_ISGID | S_ISVTX)
#   * mask is only applied to directories
def restoreattr(path, followlinks=True, mask=None):
    mask_attr = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    mask_excl = (stat.S_ISGID) if mask is None else (mask & mask_attr)
    mode_stat = os.lstat(path)[stat.ST_MODE]
    if stat.S_ISLNK(mode_stat) and not followlinks:
        return
    mode_stat = os.stat(path)[stat.ST_MODE]
    if stat.S_ISDIR(mode_stat):
        mode_perm = mode_stat & ~(mask_attr & ~mask_excl)
    else:
        mode_perm = mode_stat & ~mask_attr
    mode_perm = 0o7777 & mode_perm
    if (mode_perm) != (mode_stat & 0o7777):
        os.chmod(path, mode_perm)

# Filesystem-based permissions
#
# Restore inheritable file-system permission attributes. Usually this is just
# the setgid bit though it can be file-system and operating-system dependent.
# In all cases, only directories inherit attributes. Use the option "mask" to
# override the defaults, with the following limitations:
#   * mask must be a subset of (S_ISUID | S_ISGID | S_ISVTX)
#   * mask is only applied to directories
#
# Symbolic links are never followed. This is because there can be no guarantee
# that the canonical path (eliminating links) should in fact inherit the
# permissions - "path" may not be a descendant of "mode"'s path.
def inheritattr(mode, path, mask=None):
    mask_attr = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    mask_incl = (stat.S_ISGID) if mask is None else (mask & mask_attr)
    mode_stat = os.lstat(path)[stat.ST_MODE]
    if not stat.S_ISDIR(mode_stat):
        return
    mode_perm = (mode_stat & ~mask_incl) | (mode & mask_incl)
    mode_perm = 0o7777 & mode_perm
    if (mode_perm) != (mode_stat & 0o7777):
        os.chmod(path, mode_perm)

# Filesystem-based permissions
#
# Restore POSIX.1e ACLs from a given default ACL.
#
# Symbolic links are never followed. This is because there can be no guarantee
# that the canonical path (eliminating links) should in fact inherit the
# permissions - "path" may not be a descendant of "acl"'s path.
def inheritdacl(acl, path):
    acl_masked_entries = \
        [ posix1e.ACL_USER
        , posix1e.ACL_GROUP_OBJ
        , posix1e.ACL_GROUP
        ]
    mode_stat = os.lstat(path)[stat.ST_MODE]
    if stat.S_ISLNK(mode_stat):
        return
    acl = posix1e.ACL(acl=acl)
    acl_masked = acl_has_mask(acl)
    if not stat.S_ISDIR(mode_stat):
        for entry in acl:
            if entry.tag_type not in acl_masked_entries or not acl_masked:
                entry.permset.delete(posix1e.ACL_EXECUTE)
    acl.applyto(path, posix1e.ACL_TYPE_ACCESS)
    if stat.S_ISDIR(mode_stat):
        acl.applyto(path, posix1e.ACL_TYPE_DEFAULT)

# Discard extended ACLs
def discardeacl(path, followlinks=True):
    if os.path.islink(path) and not followlinks:
        return
    if posix1e.HAS_EXTENDED_CHECK and not posix1e.has_extended(path):
        return
    # the original approach, requiring level 2 support
    #acl = posix1e.ACL(file=path)
    #for entry in acl:
    #    if entry not in [ posix1e.ACL_USER_OBJ
    #                    , posix1e.ACL_GROUP_OBJ
    #                    , posix1e.ACL_OTHER
    #                    ]:
    #        acl.delete_entry(entry)
    #acl.applyto(path)
    #posix1e.delete_default(path)
    #assert not posix1e.has_extended(path)
    #
    # the new approach, not requiring level 2 support
    acl = posix1e.ACL()
    acl.applyto(path)
    posix1e.delete_default(path)

def restore_from_ps(mode, path):
    restoremode(path, followlinks=False, mask=stat.S_ISGID)
    inheritattr(mode, path)
    discardeacl(path, followlinks=False)

def restore_from_fs(acl, mode, path):
    restoreattr(path, followlinks=False)
    inheritattr(mode, path)
    inheritdacl(acl, path)


##############################################################################
### utilities: nzbget
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
# Matches directory or valid symbolic link to directory
if not os.path.isdir(directory):
    msg = "Nothing to post-process, destination directory \"{}\" doesn't exist."
    nzbget_log(NZBGetLogLevel.info, msg.format(directory))
    nzbget_exit(NZBGetPostProcessExitCode.none)

# Even though descendants() will walk a given directory link (only top-level),
# restore_permissions() will not properly process the link path
directory = os.path.realpath(directory)
directory_dacl = posix1e.ACL(filedef=directory)
directory_mode = os.stat(directory)[stat.ST_MODE]

if str(directory_dacl):
    restore_permissions = functools.partial\
        ( restore_from_fs
        , directory_dacl
        , directory_mode
        )
    if not posix1e.HAS_ACL_ENTRY:
        msg = "Unable to alter ACLs: detected default ACL on \"{}\""
        nzbget_log(NZBGetLogLevel.error, msg.format(directory))
        nzbget_exit(NZBGetPostProcessExitCode.failure)
    msg = "Using default ACL to restore permissions of \"{}\""
    nzbget_log(NZBGetLogLevel.info, msg.format(directory))
else:
    restore_permissions = functools.partial\
        ( restore_from_ps
        , directory_mode
        )
    msg = "Using process umask to restore permissions of \"{}\""
    nzbget_log(NZBGetLogLevel.info, msg.format(directory))

for path in descendants(directory, descendants_handler):
    try:
        restore_permissions(path)
    except FileNotFoundError as e:
        msg = "Expected path \"{}\" does not exist, aborting."
        nzbget_log(NZBGetLogLevel.error, msg.format(path))
        nzbget_exit(NZBGetPostProcessExitCode.failure)
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
