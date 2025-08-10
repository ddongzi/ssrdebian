A ShadowsRocket-like linux (debian).

1. features
- only support socks proxy, don't support http proxy

2. used libs
- `shadowsocks-libev`: ss local server.
sudo apt update
sudo apt install shadowsocks-libev

3. how to use
- firefox: set proxy manual socks5 , 
- system: set network proxy socks5
- system curl test
curl --socks5-hostname 127.0.0.1:1080 http://httpbin.org -v
curl --socks5-hostname 127.0.0.1:1080 https://youtube.com -v
curl --socks5-hostname 127.0.0.1:1080 https://www.google.com -v

4. todo
- route selection with pac