
1. Tracking comments

Ideally we'd include the text from the Debian security tracker to provide a reason why the entry was added.
For example looking at the follow extract:

"librsync": {
    "CVE-2014-8242": {
       ......

        },
        "jessie": {
          "status": "open",
          "nodsa": "Minor issue, too instrusive to backport",


Adding the text would allow a user to understand why the whitelist entry was added.


2. Handling multiple CVEs against different packages

It's possible that the same CVE may affect multiple packages and a _nodsa_ may not be noted on all versions.
This complicates CVE whitelist handling since we may need to support CVE + Package.
With Debian the CVEs are issued against source package but we whitelist against binary packages.
Ideally we'd move to a model where we can whitelist against source and/or binary packages with a format that includes
CVE, source, binary
eg.
CVE-2016-1234 linux *
which would whitelist any binary package built from linux source package with that CVE.
