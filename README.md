A ShadowsRocket-like linux (debian).

1. features
- 

2. used libs
- `shadowsocks-libev`: ss local server.
sudo apt update
sudo apt install shadowsocks-libev

3. how to use
- firefox: set proxy manual http/https  , 
- system: set network proxy http/https 

4. todo
- 

5. build
pyinstaller -F  -n ssrdebian --windowed --icon=resources/logo.png --add-data "resources/config.yml:resources" --add-data "resources/logo.png:resources" main.py