#!/bin/bash
sudo sysctl -w net.ipv4.ip_forward=1

source ~/vigilant/venv/bin/activate
nohup mitmdump --mode transparent -s ~/vigilant/nlp_filter.py > ~/vigilant/proxy.log 2>&1 &

sudo ~/vigilant/venv/bin/python ~/vigilant/app.py
