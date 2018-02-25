Installation
===
```
sudo apt-get update
sudo apt-get install cmake gcc make libleveldb1v5 libpcsclite1 libpcsclite-dev libleveldb-dev libboost-all-dev gcc g++ ntp
```


Use ntp
===
```
sudo service ntp stop
sudo apt-get install ntpdate  
sudo ntpdate pool.ntp.org
sudo service ntp start
```

Install OpenSSL 1.1
===
```
cd /usr/local/src
sudo wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz && sudo tar xzvf openssl-1.1.0g.tar.gz && cd openssl-1.1.0g
sudo ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)'
sudo make
sudo make install

openssl version # make sure it is version 1.1
```

Install UBIC
===
```
cd /usr/local/src
git clone 
cmake CMakeLists.txt
make
sudo make install
```

Run the server
===
```
/etc/init.d/ubic start
```

Stop the server
===
```
/etc/init.d/ubic stop
```
