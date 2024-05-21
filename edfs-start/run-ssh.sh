
if [ ! -d $1 ]; then
  mkdir $1
fi

cp ../populated.img populated.tmp.img
./edfuse -f populated.tmp.img $1
rm populated.tmp.img