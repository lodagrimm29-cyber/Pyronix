# Pyronix package repository

This public repository hosts the signed x86_64 Pyron package feed.

Feed base URL: `https://raw.githubusercontent.com/lodagrimm29-cyber/Pyronix/main/`
Repository ID: `pyronix-community`

The feed index (`index.json`) and signature (`index.json.sig`) are verified with the Pyronix public key (`bootstrap-public.pem`). Its SHA-256 is `8608a42381e4782c25eece2596972efc66f865b1fd4f6a4ceca0774aae49edfb`, matching this ISO's `/etc/pyron/bootstrap-repository.pem`.

The initial package is `pyronix-hello` 1.0.0 for x86_64. On Pyronix, add the feed using the base URL and trusted key, run `pyron update`, then install it with `pyron install pyronix-hello`.

This is a small pipeline demonstration. KDE Plasma and Firefox packages have not been published here yet.