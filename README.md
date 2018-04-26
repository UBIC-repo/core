# Overview
 - [Whitepaper](https://github.com/UBIC-repo/Whitepaper/blob/master/README.md)
 - [Reddit](https://www.reddit.com/r/UBIC/)
 - [Bitcointalk announcement](https://bitcointalk.org/index.php?topic=3021063.0)
 - [Installation on Linux](#installation-on-linux)
 - [Command line interface](#command-line-interface)
 - [Development environment](#development-environment)
 
# Installation on Linux

#### Install dependencies
```
sudo apt-get update
sudo apt-get install git cmake gcc make libleveldb1v5 libpcsclite1 libpcsclite-dev libleveldb-dev libboost-all-dev gcc g++ ntp
```
Verify that libboost is version >= 1.60 using ```apt-cache policy libboost-all-dev``` if it isn't run the commands bellow
```
cd /usr/local/src
sudo wget https://dl.bintray.com/boostorg/release/1.64.0/source/boost_1_64_0.tar.gz && sudo tar xzvf boost_1_64_0.tar.gz && cd boost_1_64_0
./bootstrap.sh --prefix=/usr/local --with-libraries=all
./b2 install
```

#### Use ntp
```
sudo apt-get install ntp
sudo systemctl enable ntp
```

#### Install OpenSSL 1.1
```
cd /usr/local/src
sudo wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz && sudo tar xzvf openssl-1.1.0g.tar.gz && cd openssl-1.1.0g
sudo ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)'
sudo make
sudo make install

openssl version # make sure it is version 1.1

#additional steps might be required:
sudo cp /usr/local/lib/libcrypto.so.1.1 /usr/lib
sudo cp /usr/local/lib/libssl.so.1.1 /usr/lib
```

#### Install UBIC
```
cd /usr/local/src
sudo git clone https://github.com/UBIC-repo/core.git
sudo chmod 777 -R core
cd core
cmake CMakeLists.txt
make
sudo make install
```

#### Run the server
```
/etc/init.d/ubic start
```

#### Stop the server
```
/etc/init.d/ubic stop
```

#### Open the web interface
To open the web interface you have to open 127.0.0.1:6789/#yourApiKey in your browser.

You will find your api key in the ```~/ubic/config.ini``` file.

/!\ Warning: For security reasons the web interface can not be opened remotely by typing your server ip:6789/#yourApiKey.
If you want to open the web insterface of your sever do a port forwarding over SSH, and forward the ports 6789 and 12303 to the ports 6789 and 12303 on your local machine.

#### Register a passport
To register a passport go to the "My UBI" tab and click "Register passport", then enter your passport number, date of birth and the date of expiry.
Make sure your NFC reader is plugged and ready, put the passport on top of it. To help you on some readers a green light appears when it found a tag.
Click "Register passport", if it doesnt work try again by turning your passport, opening it. If it still doesn't work open an issue on Github.

Note that to work your node should ideally be synced.

# Command line interface

```ubic web``` will get the URL for accessing the web interface.
```
Web interface: http://127.0.01:6789#839073d84f8ee9dbe98d02b3
```

```ubic status``` will get your current node status.
```
Synced: true
Blockchain height: 4114
Best block hash: 0b9751f604582ddb405e1dfa1cbf202ecbd0621b3b7f9d70ba21456675a017c8
```

```ubic add-peer <ip address>``` will add a new node to your node list.
```
Adding peer succeeded
```

```ubic peers``` will return the peers you are connected to.
```
<ip>, blockheight: <height>
```

# Development environment
UBIC was developed using CLion. If you want to work on the source code it is recommended that you use the same IDE.
