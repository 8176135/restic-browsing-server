# RBS - Restic Browsing Server
#### A server that allows you to download your files directly from the web


A lot of more automated backup services (like Backblaze), allow you to download your files from a remote computer through a web interface. 

But if you want to have more control over your backups and use restic, 
to get your files you have to have the restic binary on the machine you want the files on, and is impossible on mobile. 

---

So this is what this server does, it allows you to store your repository details (encrypted with your password) online in an account, 
and when logged in you can just browse your files and download what you need anywhere, __just as you would download any other file on the internet__.


## Encryption / Security


## The Server
#### A live server is hosted here: https://rbs.handofcthulhu.com/
or you can host it on your own VPS by cloning this repository. You would need:
1. Nightly build of `rust` (get it with `rustup`)
2. `mariadb` or `mysql` server, with `restic_browser_structure.sql` imported as a database.
3. A `database_url` file in the root directory of this repository with the connection info to the database i.e. `mysql://user:pass@127.0.0.1:3306/ResticBrowserAccounts`
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
