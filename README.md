# Simple HTTP Server (WIP)

A simple example of an linux HTTP server written in c.

# Usage

To run it as is you would just clone the repository like so

    git clone https://github.com/eric-livezey/simple-http-server.git

then navigate to the directory and run

    make

lastly, execute the file

    ./server

You should then be able to view the contents of `index.html` by visiting `http://localhost:8000/` in a browser.
You can change the port entering the port as the first arg after `./server` or by going to `server.c` and changing `#define PORT 8000` on line 7 to `#define PORT {DESIRED_PORT}`
