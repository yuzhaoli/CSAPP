#!/bin/sh
../misc/yas pingpong.ys
./psimm0 -g pingpong.yo &
./psimm1 -g pingpong.yo &

