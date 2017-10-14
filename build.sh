#!/bin/bash

function jumpto
{
    label=$1
    cmd=$(sed -n "/$label:/{
        :a
        n
        p
        ba
        };" $0 | grep -v ':$'
    )
    eval "$cmd"
    exit
}

function print_logo
{
    echo '------------------------------------------------------------'
    echo 'KICOM Anti-Virus II (for Linux) Build Tool Ver 0.11'
    echo 'Copyright (C) 1995-2017 Kei Choi. All rights reserved.'
    echo '------------------------------------------------------------'
    echo
}

start=${1:-"start"}
jumpto $start

start:
print_logo
echo 'Usage : builder.sh [build][erase]'
jumpto end

erase:
print_logo
echo '[*] Delete all files in Release'
if [ -d "Release" ]
then 
    rm -rf Release
fi

if [ -f "key.skr" ]
then 
    rm key.skr
fi

if [ -f "key.pkr" ]
then 
    rm key.pkr
fi

echo '[*] Delete Success'
jumpto end

build:
print_logo
echo '[*] Engine file copy to the Release folder...'

mkdir Release
cp -rf Engine/* Release

if [ ! -f "key.skr" ]
then 
    python Tools/mkkey.py     
fi

if [ ! -f "key.pkr" ]
then 
    python Tools/mkkey.py 
fi

cp key.* Release/plugins
cd Release/plugins

echo '[*] Build Engine files...'
python ../../Tools/kmake.py kicom.lst

for f in *.py
do
    python ../../Tools/kmake.py "$f"
done

rm *.py
rm kicom.lst
rm key.skr 
rm __init__.kmd
rm cab.kmd
rm nsis.kmd

cd ..
echo '[*] Build Success'

chmod 755 k2.py

end:
