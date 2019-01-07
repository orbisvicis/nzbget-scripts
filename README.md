Scripts for NZBGet:

* `post-process-restorecon.py`

  Restore default SELinux security contexts.

  This scripts applies `restorecon` to each successfully downloaded file and directory. The entire context (user,role,range,type) is modified, i.e. assume `-F`. For more information see `restorecon(8)`.

  Requires:

  * python3 >= 3.4
  * libselinux-python

* `post-process-restoremod.py`

  Restore default permissions.

  This script recursively restores inheritable filesystem permissions (ACLs and `setgid`) of child objects in the destination directory, `NZBPP_DIRECTORY`. This directory is always created by nzbget and never moved from the intermediate directory, even if the target consists of a single file. As such its permissions are correctly inherited from its parent and therefore used as the baseline for all child entries.

  If the destination directory contains a default ACL, then for itself and each descendant:

  * Set the inheritable permission attributes (`setgid`) from the destination directory.
  * Clear the non-inheritable permission attributes (`setuid`, `sticky`).
  * Set the ACL (and default ACL if a directory) to the default ACL of the destination directory.

  Otherwise this script assumes process-based permissions, and for the destination directory and each descendant:

  * Restore permissions, excluding the inheritable permission attribute (`setgid`), from the process `umask`.
  * Set the inheritable permission attribute (`setgid`) from the destination directory.
  * Discard any extended ACLs (certain archive formats, such as \*star, preserve ACLs).

  Before enabling this script, ensure nzbget's `umask` is compatible with that of other relevant processes. If the destination directory is modified by a third-party before this script is run, the process-based permissions this script applies might not reflect the desired permissions.

  If the destination directory is a link it will first be resolved.

  Requires:

  * python3 >= 3.4
  * pylibacl


License: GPL-3.0-or-later
