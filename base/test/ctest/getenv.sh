#!/bin/bash

board_name=$(cat /sys/class/dmi/id/board_name | tr -d '\n')
board_serial=$(cat /sys/class/dmi/id/board_serial | tr -d '\n')
board_vendor=$(cat /sys/class/dmi/id/board_vendor | tr -d '\n')
product_name=$(cat /sys/class/dmi/id/product_name | tr -d '\n')
product_version=$(cat /sys/class/dmi/id/product_version | tr -d '\n')
product_serial=$(cat /sys/class/dmi/id/product_serial | tr -d '\n')
product_uuid=$(cat /sys/class/dmi/id/product_uuid | tr -d '\n')

output="board_name:${board_name},board_serial:${board_serial},board_vendor:${board_vendor},product_name:${product_name},product_version:${product_version},product_serial:${product_serial},product_uuid:${product_uuid}"

echo ${output} > license_env.txt
