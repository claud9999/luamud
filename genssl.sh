#!/bin/bash

openssl req -newkey rsa:2048 -nodes -keyout luamud.key -x509 -days 10000 -out luamud.crt -subj "/C=US/ST=California/L=San Jose/O=LuaMUD/CN=localhost"
