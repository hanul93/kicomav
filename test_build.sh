mkdir Release
mkdir Release/plugins

cp Engine/* Release
cp Engine/plugins/* Release/plugins

cp Tool/kmake.py Release/plugins
cp Sample/* Release
cd Release/plugins

python kmake.py kicom.lst
python kmake.py ole.py
python kmake.py dummy.py
python kmake.py eicar.py

rm -rf *.pyc
rm -rf kicom.lst

cp ole.py ..
cd ..

cp ../Test/* .

