# RBS - Restic Browsing Server
#### A server that allows you to download your files directly from the web


A lot of more automated backup services (like Backblaze), allow you to download your files from a remote computer through a web interface. 

But if you want to have more control over your backups and use restic, 
to get your files you have to have the restic binary on the machine you want the files on, and is impossible on mobile. 

---

So this is what this server does, it allows you to store your repository details (encrypted with your password) online in an account, 
and when logged in you can just browse your files and download what you need anywhere, __just as you would download any other file on the internet__.


## Encryption / Security

All sensitive data stored on the server database is encrypted, including:
- Repository encryption password
- Environment variables values used when calling restic.
- The address of the remote repository.

They are encrypted by a random 256-bit master key generated securely upon registration, 
which is then encrypted by your password with `ChaCha20` so no one can retrieve your data apart from you even if they have access to the database.

When logged in your session is stored on the server as your master key encrypted again with another random key, the key is then stored on your computer as a cookie, 
used to authenticate you and decrypt the master key every time you communicate with the server.

I'm not a security expert, so if you find any problems, please open an issue.


## The Server
#### A live server is hosted here: https://rbs.handofcthulhu.com/
or you can host it on your own VPS by cloning this repository. You would need:
1. Nightly build of `rust` (get it with `rustup`)
2. `mariadb` or `mysql` server, with `restic_browser_structure.sql` imported as a database.
3. A `rbs_config.json` file in the starting directory of the server with the configuration info, see `example/rbs_config.json` 
4. A `Rocket.toml` file to configure the port and address you want to run the server on, i.e.
    ```
         [development]
         address = "0.0.0.0"
         port = 8000
        
         [production]
         secret_key = "<256-bit key>"
         address = "127.0.0.1"
         port = 12345
    ```
5. A reverse proxy for https (like `nginx`)

Then run `cargo build +nightly --release` to build, then just make sure `Rocket.toml` is in the starting directory of the server, and things should work.

(You might want to change the google analytics header in each handlebars (`.hbs`) file)