#!/bin/sh
# имитация zsign: находит -o и копирует последний аргумент (входной IPA)
while [ $# -gt 1 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
cp "$1" "$out"
