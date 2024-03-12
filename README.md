# Simple HTTP Server
A simple example of an HTTP server written in c.
# Usage
To run it as is you would juts clone the repository
```
clone https://github.com/eric-livezey/simple-http-server.git
```
then navigate to the directory and run
```
make
```
lastly, execute the file
```
./server
```
You should then be able to view the contents of `index.html` by visiting `http://localhost:8000/` in a browser.
You can change the port by going to `server.c` and changing `#define PORT 8000` on line 14 to `#define PORT {DESIRED_PORT}`
