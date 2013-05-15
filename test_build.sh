mkdir Release
cp Engine/* Release
cp Tool/* Release
cp Sample/* Release
cd Release
python kmake.py curemod.py
rm -rf *.pyc
rm -rf curemod.py
rm -rf kmake.py
cp * ../Test
