#!/bin/bash

echo '------------------------------------------------------------'
echo 'KICOM Anti-Virus II (for Linux) Build Tool Ver 0.10'
echo 'Copyright (C) 1995-2016 Kei Choi. All rights reserved.'
echo '------------------------------------------------------------'

if [ -d "Release" ]
then 
    rm -rf Release
fi

mkdir Release
cp -rf Engine/* Release

if [ -f "key.skr" ]
then 
    rm key.skr
fi

if [ -f "key.pkr" ]
then 
    rm key.pkr
fi

python Tool/mkkey.py 

cp key.* Release/plugins
cp Tool/kmake.py Release/plugins
cd Release/plugins

echo '[*] Build Engine files...'
python kmake.py kicom.lst

for f in *.py
do
    python kmake.py "$f"
done

mv key.pkr kicomav.pkr
rm *.py
rm kicom.lst
rm key.skr 

echo '[*] Build Success'