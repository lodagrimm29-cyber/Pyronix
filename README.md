# Pyronix package repository

This public repository hosts the signed x86_64 Pyron package feed.

Feed base URL: `https://raw.githubusercontent.com/lodagrimm29-cyber/Pyronix/main/`
Repository ID: `pyronix-community`

The feed index (`index.json`) and signature (`index.json.sig`) are verified with the Pyronix public key (`bootstrap-public.pem`). Its SHA-256 is `8608a42381e4782c25eece2596972efc66f865b1fd4f6a4ceca0774aae49edfb`, matching this ISO's `/etc/pyron/bootstrap-repository.pem`.

The initial package is `pyronix-hello` 1.0.0 for x86_64. The feed also provides `pyron-manager-update` 1.0.0. On a running Pyronix system with this feed configured, run `sudo pyron update`, then `sudo pyron install pyron-manager-update`, followed by `sudo pyron self-update`. This update uses BusyBox gzip when Python's optional zlib module is missing, backs up the current manager before atomically activating the new one, and raises the maximum individual package file size to 256 MiB for large optional packages.

This updates the running system's writable filesystem only. A live ISO session may lose the update at reboot; this repository update does not rebuild or modify the ISO.

This is a small pipeline demonstration. KDE Plasma and Firefox packages have not been published here yet.
