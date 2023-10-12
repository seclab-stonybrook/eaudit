fatal() {
  echo "BCC installation failed at the following step: $1"
  exit 1
}

sudo apt update || fatal "apt update"
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev \
  python3-setuptools liblzma-dev libdebuginfod-dev \
  || fatal "apt install (of required development packages)"
mkdir src || fatal "mkdir"
cd src
git clone https://github.com/iovisor/bcc.git || fatal "cloning BCC source from iovisor"
mkdir bcc/build; cd bcc/build 
cmake .. || fatal "cmake"
make || fatal "Building BCC from source"
sudo make install || fatal "installing BCC"
cmake -DPYTHON_CMD=python3 .. || fatal "building python3 bindings"
pushd src/python/
( make && sudo make install ) || fatal "installing python bindings"
